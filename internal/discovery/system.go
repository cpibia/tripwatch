package discovery

import (
	"bufio"
	"bytes"
	"io/fs"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// System is what identifies the observed machine to whoever runs the fleet: distribution,
// kernel, resources, addresses and the sensor's own version. Everything but the version and the
// architecture is read from files root can rewrite, so the verifier shows it as data.
type System struct {
	OS            string    `json:"os,omitempty"`
	OSID          string    `json:"os_id,omitempty"`
	OSVersion     string    `json:"os_version,omitempty"`
	Kernel        string    `json:"kernel,omitempty"`
	Arch          string    `json:"arch"`
	Hostname      string    `json:"hostname,omitempty"`
	BootedAt      time.Time `json:"booted_at,omitzero"`
	CPUs          int       `json:"cpus,omitempty"`
	MemoryBytes   uint64    `json:"memory_bytes,omitempty"`
	Addresses     []string  `json:"addresses,omitempty"`
	SensorVersion string    `json:"sensor_version"`
}

// Bounds on what the system block carries: values come from files the host controls.
const (
	maxSystemValue = 200
	maxAddresses   = 16
)

// DetectSystem reads the system block from the observed root, with the sensor's version and the
// addresses of its network interfaces.
func DetectSystem(root fs.FS, sensorVersion string, addresses []string) System {
	s := System{Arch: runtime.GOARCH, SensorVersion: sensorVersion}
	osRelease := readSmall(root, "etc/os-release")
	if osRelease == nil {
		osRelease = readSmall(root, "usr/lib/os-release")
	}
	fields := osReleaseFields(osRelease)
	s.OS, s.OSID, s.OSVersion = clipValue(fields["PRETTY_NAME"]), clipValue(fields["ID"]), clipValue(fields["VERSION_ID"])
	if s.OS == "" {
		s.OS = clipValue(strings.TrimSpace(fields["NAME"] + " " + fields["VERSION_ID"]))
	}
	s.Kernel = clipValue(strings.TrimSpace(string(readSmall(root, "proc/sys/kernel/osrelease"))))
	s.Hostname = clipValue(strings.TrimSpace(string(readSmall(root, "proc/sys/kernel/hostname"))))
	if s.Hostname == "" {
		s.Hostname = clipValue(strings.TrimSpace(string(readSmall(root, "etc/hostname"))))
	}
	for _, line := range lines(readSmall(root, "proc/stat")) {
		if v, ok := strings.CutPrefix(line, "btime "); ok {
			if secs, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil && secs > 0 {
				s.BootedAt = time.Unix(secs, 0).UTC()
			}
		}
	}
	for _, line := range lines(readSmall(root, "proc/cpuinfo")) {
		if strings.HasPrefix(line, "processor") {
			s.CPUs++
		}
	}
	for _, line := range lines(readSmall(root, "proc/meminfo")) {
		if v, ok := strings.CutPrefix(line, "MemTotal:"); ok {
			if kb, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimSpace(v), " kB"), 10, 64); err == nil {
				s.MemoryBytes = kb * 1024
			}
		}
	}
	for _, a := range addresses {
		if len(s.Addresses) == maxAddresses {
			break
		}
		s.Addresses = append(s.Addresses, clipValue(a))
	}
	return s
}

// readSmall reads a small system file, or nil when it is missing or not a plain small file.
func readSmall(root fs.FS, name string) []byte {
	b, err := fs.ReadFile(root, name)
	if err != nil || len(b) > 1<<20 {
		return nil
	}
	return b
}

// osReleaseFields parses os-release: KEY=value lines, values optionally quoted.
func osReleaseFields(b []byte) map[string]string {
	out := map[string]string{}
	for _, line := range lines(b) {
		k, v, ok := strings.Cut(line, "=")
		if !ok || strings.HasPrefix(k, "#") {
			continue
		}
		if uq, err := strconv.Unquote(v); err == nil {
			v = uq
		} else {
			v = strings.Trim(v, `"'`)
		}
		out[strings.TrimSpace(k)] = v
	}
	return out
}

func lines(b []byte) []string {
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 4096), 1<<20)
	for sc.Scan() {
		out = append(out, sc.Text())
	}
	return out
}

func clipValue(s string) string {
	if len(s) > maxSystemValue {
		s = s[:maxSystemValue]
	}
	return strings.ToValidUTF8(s, "")
}
