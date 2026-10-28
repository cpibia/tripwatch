package protocol

import (
	"crypto/ed25519"
	"strings"
	"testing"
	"time"
)

// An update order verifies only under the key that signed it, unchanged, and only when every
// entry is a sensor file with a SHA-256.
func TestUpdateOrderSignature(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(nil)
	other, _, _ := ed25519.GenerateKey(nil)
	order := UpdateOrder{Version: "0.2.0", Sums: map[string]string{"tripwatch-sensor_0.2.0_amd64.deb": strings.Repeat("ab", 32)}, IssuedAt: time.Unix(1, 0).UTC()}
	payload, sig, err := SignUpdate(order, key)
	if err != nil {
		t.Fatal(err)
	}
	got, err := VerifyUpdate(payload, sig, pub)
	if err != nil || got.Version != "0.2.0" || len(got.Sums) != 1 {
		t.Fatalf("got %+v, %v", got, err)
	}
	if _, err := VerifyUpdate(payload, sig, other); err == nil {
		t.Error("verified under another key")
	}
	if _, err := VerifyUpdate(payload[:len(payload)-2]+"AA", sig, pub); err == nil {
		t.Error("a changed order verified")
	}
	for _, bad := range []UpdateOrder{
		{Version: "0.2", Sums: order.Sums},
		{Version: "0.2.0"},
		{Version: "0.2.0", Sums: map[string]string{"../../etc/passwd": strings.Repeat("ab", 32)}},
		{Version: "0.2.0", Sums: map[string]string{"tripwatch-sensor_x": "not a hash"}},
	} {
		if _, _, err := SignUpdate(bad, key); err == nil {
			t.Errorf("signed %+v", bad)
		}
	}
}

// An uninstall order acts only on the host it names, under the key that signed it.
func TestUninstallOrderNamesItsHost(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(nil)
	other, _, _ := ed25519.GenerateKey(nil)
	payload, sig, err := SignUninstall(UninstallOrder{HostID: "web-01", IssuedAt: time.Unix(1, 0).UTC()}, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyUninstall(payload, sig, pub, "web-01"); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyUninstall(payload, sig, pub, "web-02"); err == nil {
		t.Error("an order for another host verified")
	}
	if _, err := VerifyUninstall(payload, sig, other, "web-01"); err == nil {
		t.Error("verified under another key")
	}
	if _, _, err := SignUpdate(UpdateOrder{}, key); err == nil {
		t.Error("an empty update order was signed")
	}
	// The two kinds of order are signed under different domains: one cannot pass for the other.
	if _, err := VerifyUpdate(payload, sig, pub); err == nil {
		t.Error("an uninstall order verified as an update order")
	}
}
