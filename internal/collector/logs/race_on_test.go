//go:build race

package logs

// The race detector slows the memory flood test twentyfold; CI runs it in a separate step
// without the detector.
const raceEnabled = true
