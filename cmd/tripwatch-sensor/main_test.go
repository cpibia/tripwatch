package main

import "testing"

// The bridges and virtual links of container runtimes carry the same addresses on every host and
// are left out; the machine's own interfaces are kept.
func TestContainerInterface(t *testing.T) {
	for name, want := range map[string]bool{"docker0": true, "br-3f2a9c1d": true, "veth9a1b2c": true, "cni0": true, "cali7f": true, "virbr0": true,
		"eth0": false, "ens5": false, "enp0s3": false, "wlan0": false, "bond0": false} {
		if got := containerInterface(name); got != want {
			t.Errorf("%s: %v, want %v", name, got, want)
		}
	}
}
