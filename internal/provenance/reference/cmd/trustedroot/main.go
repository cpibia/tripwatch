// Command trustedroot prints the trusted_root.json of Sigstore's public-good instance, fetched
// through TUF from the root sigstore-go ships: the trust root the sensor embeds.
package main

import (
	"fmt"
	"os"

	"github.com/sigstore/sigstore-go/pkg/tuf"
)

func main() {
	client, err := tuf.New(tuf.DefaultOptions().WithDisableLocalCache())
	if err == nil {
		var root []byte
		if root, err = client.GetTarget("trusted_root.json"); err == nil {
			_, err = os.Stdout.Write(root)
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "trustedroot:", err)
		os.Exit(1)
	}
}
