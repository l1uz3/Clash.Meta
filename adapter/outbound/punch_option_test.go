package outbound

import (
	"testing"

	"github.com/metacubex/mihomo/common/structure"
)

// The punch block is opt-in: proxies without it must keep the normal dialer, and a proxy
// with it must decode into BasicOption.Punch through mihomo's own option decoder.
func TestBasicOptionDecodesPunchBlock(t *testing.T) {
	decoder := structure.NewDecoder(structure.Option{TagName: "proxy", WeaklyTypedInput: true})
	fp := "0000000000000000000000000000000000000000000000000000000000000000"

	var with ShadowSocksOption
	err := decoder.Decode(map[string]any{
		"name": "p", "server": "0.0.0.0", "port": 1, "cipher": "aes-128-gcm", "password": "x",
		"punch": map[string]any{"coordinator": "example.invalid:48080", "fingerprint": fp, "token": "t", "keep": 2},
	}, &with)
	if err != nil {
		t.Fatal(err)
	}
	if with.Punch == nil || with.Punch.Coordinator != "example.invalid:48080" || with.Punch.Keep != 2 {
		t.Fatalf("punch block not decoded: %+v", with.Punch)
	}

	var without ShadowSocksOption
	if err := decoder.Decode(map[string]any{"name": "p", "server": "0.0.0.0", "port": 1, "cipher": "aes-128-gcm", "password": "x"}, &without); err != nil {
		t.Fatal(err)
	}
	if without.Punch != nil {
		t.Fatal("punch must stay nil when not configured")
	}
}
