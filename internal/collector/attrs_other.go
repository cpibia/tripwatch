//go:build !(linux && (amd64 || arm64))

package collector

// ReadAttrs is only implemented on 64-bit Linux, the platforms the sensor ships for.
func ReadAttrs(string) (Attrs, error) {
	return Attrs{}, ErrAttrsUnsupported
}
