// Package punch provides a C.Dialer that reaches a server behind an allow-list firewall
// (one that only admits connections it initiated itself) by TCP simultaneous-open
// hole punching, coordinated through a separate rendezvous server.
//
// The dialer keeps a small pool of punched TCP connections to the server-side agent,
// multiplexes outbound connections over them with yamux, and refreshes the pool before
// stateful middleboxes expire the punched flows. No server address, token or
// credential is built in: everything comes from the proxy configuration.
package punch

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/metacubex/mihomo/component/dialer"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

// Option is the "punch" block of a proxy.
type Option struct {
	Coordinator string `proxy:"coordinator"`               // host:port of the rendezvous TLS port
	Fingerprint string `proxy:"fingerprint"`               // SHA-256 of the coordinator certificate
	Token       string `proxy:"token"`                     // per-user token issued by the server owner
	ProbePorts  []int  `proxy:"probe-ports,omitempty"`     // two plaintext NAT-probe ports (default 48082, 48084)
	Attempts    int    `proxy:"attempts,omitempty"`        // tuples opened per punch round (default 4)
	Keep        int    `proxy:"keep,omitempty"`            // tuples kept per round (default 2)
	Refresh     int    `proxy:"refresh,omitempty"`         // seconds before the youngest session is refreshed (default 60)
	MaxAge      int    `proxy:"max-age,omitempty"`         // seconds before a session stops taking new streams (default 110)
	LocalPort   int    `proxy:"local-port-base,omitempty"` // first local port for punch tuples (default 50111)
}

func (o *Option) withDefaults() (Option, error) {
	v := *o
	if v.Coordinator == "" || v.Token == "" {
		return v, errors.New("punch: coordinator and token are required")
	}
	fp := strings.ToLower(strings.ReplaceAll(v.Fingerprint, ":", ""))
	if len(fp) != 64 {
		return v, errors.New("punch: fingerprint must be the 64-hex SHA-256 of the coordinator certificate")
	}
	v.Fingerprint = fp
	if len(v.ProbePorts) != 2 {
		v.ProbePorts = []int{48082, 48084}
	}
	if v.Attempts <= 0 {
		v.Attempts = 4
	}
	if v.Keep <= 0 {
		v.Keep = 2
	}
	if v.Attempts < v.Keep {
		v.Attempts = v.Keep
	}
	if v.Refresh <= 0 {
		v.Refresh = 60
	}
	if v.MaxAge <= v.Refresh {
		v.MaxAge = v.Refresh + 50
	}
	if v.LocalPort <= 0 {
		v.LocalPort = 50111
	}
	return v, nil
}

// pools are shared per coordinator+token, so several proxies pointing at the same
// server reuse one set of punched sessions.
var (
	poolsMu sync.Mutex
	pools   = map[string]*pool{}
)

// NewDialer returns a C.Dialer that carries every DialContext over the punched pool.
func NewDialer(o Option) (C.Dialer, error) {
	v, err := o.withDefaults()
	if err != nil {
		return nil, err
	}
	key := v.Coordinator + "|" + v.Token
	poolsMu.Lock()
	defer poolsMu.Unlock()
	p, ok := pools[key]
	if !ok {
		p = newPool(v)
		pools[key] = p
	}
	return &punchDialer{p: p}, nil
}

// NetworkChanged drops every pool's sessions and forgets the cached NAT type, so the next
// dial re-probes the new network instead of reusing a Wi-Fi verdict on mobile data.
func NetworkChanged() {
	poolsMu.Lock()
	defer poolsMu.Unlock()
	for _, p := range pools {
		p.reset()
	}
}

type punchDialer struct{ p *pool }

type errorDialer struct{ err error }

// ErrorDialer returns a dialer that always fails with err, so a misconfigured punch proxy
// reports its problem instead of falling back to a direct dial.
func ErrorDialer(err error) C.Dialer { return errorDialer{err} }

func (d errorDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, d.err
}

func (d errorDialer) ListenPacket(context.Context, string, string, netip.AddrPort) (net.PacketConn, error) {
	return nil, d.err
}

func (d *punchDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if !strings.HasPrefix(network, "tcp") {
		return nil, fmt.Errorf("punch: %s unsupported, enable smux/udp-over-tcp for UDP", network)
	}
	return d.p.openStream(ctx)
}

func (d *punchDialer) ListenPacket(context.Context, string, string, netip.AddrPort) (net.PacketConn, error) {
	return nil, errors.New("punch: UDP is not carried; enable smux or udp-over-tcp on the proxy")
}

// ---------------- session pool ----------------

type session struct {
	s       *yamux.Session
	born    time.Time
	retired bool
}

type pool struct {
	opt  Option
	mu   sync.Mutex
	sess []*session
	rr   int

	natMode string // "", "cone", "symmetric"
	base    int
	kick    chan struct{}
	once    sync.Once
}

func newPool(o Option) *pool {
	return &pool{opt: o, base: o.LocalPort, kick: make(chan struct{}, 1)}
}

func (p *pool) start() { p.once.Do(func() { go p.maintain() }) }

func (p *pool) reset() {
	p.mu.Lock()
	for _, s := range p.sess {
		s.s.Close()
	}
	p.sess = nil
	p.natMode = ""
	p.mu.Unlock()
	select {
	case p.kick <- struct{}{}:
	default:
	}
}

func (p *pool) add(s *yamux.Session) {
	p.mu.Lock()
	p.sess = append(p.sess, &session{s: s, born: time.Now()})
	p.mu.Unlock()
}

// usable prunes dead/drained sessions and returns how many still take new streams.
func (p *pool) usable() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := p.sess[:0]
	n := 0
	for _, s := range p.sess {
		if s.s.IsClosed() {
			continue
		}
		if s.retired && s.s.NumStreams() == 0 {
			s.s.Close()
			continue
		}
		out = append(out, s)
		if !s.retired {
			n++
		}
	}
	p.sess = out
	return n
}

func (p *pool) newestAge() time.Duration {
	p.mu.Lock()
	defer p.mu.Unlock()
	best := time.Duration(1 << 62)
	for _, s := range p.sess {
		if !s.retired && !s.s.IsClosed() {
			if a := time.Since(s.born); a < best {
				best = a
			}
		}
	}
	return best
}

func (p *pool) retireOlderThan(d time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, s := range p.sess {
		if !s.retired && time.Since(s.born) > d {
			s.retired = true
		}
	}
}

// openStream waits briefly for a usable session, then opens a stream on the youngest batch:
// the router holds the freshest state for it.
func (p *pool) openStream(ctx context.Context) (net.Conn, error) {
	p.start()
	deadline := time.Now().Add(20 * time.Second)
	for {
		if st, err := p.tryOpen(); err == nil {
			return st, nil
		}
		if time.Now().After(deadline) {
			return nil, errors.New("punch: no tunnel session available")
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func (p *pool) tryOpen() (net.Conn, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	var cand []*session
	for _, s := range p.sess {
		if !s.retired && !s.s.IsClosed() {
			cand = append(cand, s)
		}
	}
	if len(cand) == 0 {
		return nil, errors.New("empty")
	}
	newest := cand[0].born
	for _, s := range cand {
		if s.born.After(newest) {
			newest = s.born
		}
	}
	var batch []*session
	for _, s := range cand {
		if newest.Sub(s.born) < 5*time.Second {
			batch = append(batch, s)
		}
	}
	for i := 0; i < len(batch); i++ {
		p.rr = (p.rr + 1) % len(batch)
		if st, err := batch[p.rr].s.OpenStream(); err == nil {
			return st, nil
		}
	}
	for _, s := range cand {
		if st, err := s.s.OpenStream(); err == nil {
			return st, nil
		}
	}
	return nil, errors.New("open failed")
}

func (p *pool) maintain() {
	refresh := time.Duration(p.opt.Refresh) * time.Second
	maxAge := time.Duration(p.opt.MaxAge) * time.Second
	for {
		if p.usable() > 0 && p.newestAge() < refresh {
			p.retireOlderThan(maxAge)
			select {
			case <-p.kick:
			case <-time.After(3 * time.Second):
			}
			continue
		}
		p.base += 20
		if p.base > 60000 {
			p.base = p.opt.LocalPort
		}
		p.mu.Lock()
		mode := p.natMode
		p.mu.Unlock()
		if mode == "" {
			mode = p.detectNAT()
			log.Infoln("[punch] NAT type: %s", mode)
			p.mu.Lock()
			p.natMode = mode
			p.mu.Unlock()
		}
		n := 0
		if mode == "cone" {
			for i := 1; i <= p.opt.Attempts && n < p.opt.Keep; i++ {
				if p.punchDirect(p.base + i) {
					n++
				}
			}
			if n == 0 {
				mode = "symmetric"
				p.mu.Lock()
				p.natMode = mode
				p.mu.Unlock()
			}
		}
		if mode != "cone" {
			n += p.punchPredict(p.base, p.opt.Keep-n)
		}
		if n == 0 {
			log.Warnln("[punch] round produced no session; retrying")
			p.mu.Lock()
			p.natMode = "" // the network may have changed; re-probe next round
			p.mu.Unlock()
			time.Sleep(5 * time.Second)
		} else {
			log.Infoln("[punch] added %d session(s)", n)
		}
	}
}

// ---------------- protected sockets ----------------

// netDialer binds a fixed local port with SO_REUSEADDR/PORT (needed for simultaneous open).
// It is passed through mihomo's dialer, which chains its own socket hook after our Control,
// so on Android every punch socket is still handed to VpnService.protect() and bypasses the tun.
func netDialer(localPort int, timeout time.Duration) *net.Dialer {
	return &net.Dialer{
		LocalAddr: &net.TCPAddr{Port: localPort},
		Timeout:   timeout,
		Control: func(network, address string, c syscall.RawConn) error {
			var serr error
			c.Control(func(fd uintptr) {
				serr = setReuse(int(fd))
			})
			return serr
		},
	}
}

func dialFrom(ctx context.Context, localPort int, address string, timeout time.Duration) (net.Conn, error) {
	return dialer.DialContext(ctx, "tcp", address, dialer.WithNetDialer(netDialer(localPort, timeout)))
}

func dialPlain(ctx context.Context, address string, timeout time.Duration) (net.Conn, error) {
	return dialer.DialContext(ctx, "tcp", address, dialer.WithNetDialer(&net.Dialer{Timeout: timeout}))
}

// ---------------- control channel ----------------

func (p *pool) tlsWrap(raw net.Conn) (net.Conn, error) {
	pin := p.opt.Fingerprint
	tc := tls.Client(raw, &tls.Config{
		InsecureSkipVerify: true, // self-signed coordinator; trust is the pin below
		MinVersion:         tls.VersionTLS13,
		VerifyPeerCertificate: func(certs [][]byte, _ [][]*x509.Certificate) error {
			if len(certs) == 0 {
				return errors.New("no coordinator certificate")
			}
			got := sha256.Sum256(certs[0])
			if subtle.ConstantTimeCompare([]byte(hex.EncodeToString(got[:])), []byte(pin)) != 1 {
				return errors.New("coordinator fingerprint mismatch")
			}
			return nil
		},
	})
	tc.SetDeadline(time.Now().Add(15 * time.Second))
	if err := tc.Handshake(); err != nil {
		tc.Close()
		return nil, err
	}
	tc.SetDeadline(time.Time{})
	return tc, nil
}

func (p *pool) dialCoord(localPort int) (net.Conn, error) {
	raw, err := dialFrom(context.Background(), localPort, p.opt.Coordinator, 10*time.Second)
	if err != nil {
		return nil, err
	}
	return p.tlsWrap(raw)
}

func readLine(c net.Conn, br *bufio.Reader, d time.Duration) (string, error) {
	c.SetReadDeadline(time.Now().Add(d))
	l, err := br.ReadString('\n')
	c.SetReadDeadline(time.Time{})
	return strings.TrimSpace(l), err
}

// detectNAT compares the public port two plaintext probe listeners see from one local port.
func (p *pool) detectNAT() string {
	host, _, err := net.SplitHostPort(p.opt.Coordinator)
	if err != nil {
		return "symmetric"
	}
	lp := 42000 + int(time.Now().UnixNano()%6000)
	see := func(port int) string {
		c, err := dialFrom(context.Background(), lp, net.JoinHostPort(host, strconv.Itoa(port)), 6*time.Second)
		if err != nil {
			return ""
		}
		defer c.Close()
		l, _ := readLine(c, bufio.NewReader(c), 5*time.Second)
		if f := strings.Fields(l); len(f) == 2 {
			return f[1]
		}
		return ""
	}
	a, b := see(p.opt.ProbePorts[0]), see(p.opt.ProbePorts[1])
	switch {
	case a == "" || b == "":
		return "symmetric" // unknown: take the path that works on any NAT
	case a == b:
		return "cone"
	default:
		return "symmetric"
	}
}

// ---------------- punch rounds ----------------

func yamuxCfg() *yamux.Config {
	c := yamux.DefaultConfig()
	c.EnableKeepAlive = true
	c.KeepAliveInterval = 10 * time.Second // doubles as the NAT keepalive
	c.ConnectionWriteTimeout = 20 * time.Second
	c.LogOutput = io.Discard
	return c
}

// punchDirect: port-preserving NAT, no whitelist. The coordinator sees our public port on the
// control connection and has the server dial it back from a fixed source port.
func (p *pool) punchDirect(localPort int) bool {
	ctrl, err := p.dialCoord(localPort)
	if err != nil {
		log.Warnln("[punch] coordinator unreachable: %v", err)
		return false
	}
	defer ctrl.Close()
	fmt.Fprintf(ctrl, "HELLO %s ctunnel\n", p.opt.Token)
	br := bufio.NewReader(ctrl)
	l, err := readLine(ctrl, br, 15*time.Second)
	f := strings.Fields(l)
	if err != nil || len(f) < 3 || f[0] != "ASSIGN" {
		return false
	}
	conn, err := punchRetry(localPort, net.JoinHostPort(f[1], f[2]), 8*time.Second)
	if err != nil {
		return false
	}
	sess, err := yamux.Client(conn, yamuxCfg())
	if err != nil {
		conn.Close()
		return false
	}
	p.add(sess)
	return true
}

// punchPredict: symmetric NAT. The coordinator whitelists us briefly (over a relayed socket so
// its firewall token never reaches this device), the server learns our NAT's port and climb rate
// from two sacrificial SYNs, then dials back the fresh tuples it predicts. Keeps up to `keep`.
func (p *pool) punchPredict(localPort, keep int) int {
	if keep < 1 {
		return 0
	}
	ctrl, err := p.dialCoord(localPort)
	if err != nil {
		log.Warnln("[punch] coordinator unreachable: %v", err)
		return 0
	}
	defer ctrl.Close()
	fmt.Fprintf(ctrl, "HELLO %s tunnel 300 6 %d 0 0 %d\n", p.opt.Token, p.opt.Attempts, keep)
	br := bufio.NewReader(ctrl)

	l, err := readLine(ctrl, br, 20*time.Second)
	f := strings.Fields(l)
	if err != nil || len(f) != 5 || f[0] != "WLRELAY" {
		log.Warnln("[punch] coordinator refused: %q", l)
		return 0
	}
	rid, addHP, serverIP, tport := f[1], f[2], f[3], f[4]
	if err := p.relayWhitelist(addHP, rid); err != nil {
		log.Warnln("[punch] whitelist relay failed: %v", err)
		return 0
	}
	if l, err = readLine(ctrl, br, 30*time.Second); err != nil || !strings.HasPrefix(l, "WLOK ") {
		return 0
	}
	if l, err = readLine(ctrl, br, 30*time.Second); err != nil || l != "GO" {
		return 0
	}
	remote := net.JoinHostPort(serverIP, tport)

	sctx, scancel := context.WithCancel(context.Background())
	sac := func(lp int) {
		if c, err := dialFrom(sctx, lp, remote, 40*time.Second); err == nil {
			c.Close()
		}
	}
	go sac(localPort)
	go func() {
		select {
		case <-sctx.Done():
		case <-time.After(2200 * time.Millisecond):
			sac(localPort + 1)
		}
	}()
	l, err = readLine(ctrl, br, 40*time.Second)
	scancel()
	if err != nil || !strings.HasPrefix(l, "PREDICT ") {
		return 0
	}
	n := p.opt.Attempts
	time.Sleep(200 * time.Millisecond)
	fmt.Fprintf(ctrl, "FRESH local=%d..%d\n", localPort+2, localPort+1+n)
	go func() { io.Copy(io.Discard, br) }()

	var wg sync.WaitGroup
	var mu sync.Mutex
	kept := 0
	for i := 1; i <= n; i++ {
		wg.Add(1)
		go func(lp int) {
			defer wg.Done()
			c, err := dialFrom(context.Background(), lp, remote, 25*time.Second)
			if err != nil {
				return
			}
			mu.Lock()
			full := kept >= keep
			if !full {
				kept++
			}
			mu.Unlock()
			if full {
				c.Close()
				return
			}
			sess, err := yamux.Client(c, yamuxCfg())
			if err != nil {
				c.Close()
				return
			}
			p.add(sess)
		}(localPort + 1 + i)
		time.Sleep(30 * time.Millisecond)
	}
	wg.Wait()
	return kept
}

// relayWhitelist opens a raw socket to the firewall's add endpoint and splices it to a TLS
// relay connection on the coordinator, which runs TLS + the request over it. The add endpoint
// sees this device's IP; the token only exists inside TLS this device cannot read.
func (p *pool) relayWhitelist(addHP, rid string) error {
	up, err := dialPlain(context.Background(), addHP, 10*time.Second)
	if err != nil {
		return err
	}
	raw, err := dialPlain(context.Background(), p.opt.Coordinator, 10*time.Second)
	if err != nil {
		up.Close()
		return err
	}
	cc, err := p.tlsWrap(raw)
	if err != nil {
		up.Close()
		return err
	}
	fmt.Fprintf(cc, "RELAY %s\n", rid)
	go func() {
		done := make(chan struct{}, 2)
		go func() { io.Copy(cc, up); cc.Close(); up.Close(); done <- struct{}{} }()
		go func() { io.Copy(up, cc); cc.Close(); up.Close(); done <- struct{}{} }()
		<-done
	}()
	return nil
}

// punchRetry repeats a simultaneous-open connect from localPort until it lands or times out.
func punchRetry(localPort int, remote string, total time.Duration) (net.Conn, error) {
	deadline := time.Now().Add(total)
	var last error
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		c, err := dialFrom(ctx, localPort, remote, 2*time.Second)
		cancel()
		if err == nil {
			return c, nil
		}
		last = err
		time.Sleep(200 * time.Millisecond)
	}
	return nil, last
}
