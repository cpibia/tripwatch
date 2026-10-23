package discovery

import (
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

func TestDetectSystem(t *testing.T) {
	root := fstest.MapFS{
		"etc/os-release":            {Data: []byte("NAME=\"Amazon Linux\"\nVERSION_ID=\"2023\"\nID=\"amzn\"\nPRETTY_NAME=\"Amazon Linux 2023.6.20241010\"\n")},
		"proc/sys/kernel/osrelease": {Data: []byte("6.1.112-124.190.amzn2023.x86_64\n")},
		"proc/sys/kernel/hostname":  {Data: []byte("web-01\n")},
		"proc/stat":                 {Data: []byte("cpu  1 2 3\nbtime 1729670400\nprocesses 42\n")},
		"proc/cpuinfo":              {Data: []byte("processor\t: 0\nmodel name\t: x\n\nprocessor\t: 1\nmodel name\t: x\n")},
		"proc/meminfo":              {Data: []byte("MemTotal:        4010252 kB\nMemFree: 1 kB\n")},
	}
	s := DetectSystem(root, "0.1.8", []string{"172.31.42.150", "2001:db8::5"})
	if s.OS != "Amazon Linux 2023.6.20241010" || s.OSID != "amzn" || s.OSVersion != "2023" {
		t.Errorf("os = %q %q %q", s.OS, s.OSID, s.OSVersion)
	}
	if s.Kernel != "6.1.112-124.190.amzn2023.x86_64" || s.Hostname != "web-01" || s.CPUs != 2 || s.MemoryBytes != 4010252*1024 {
		t.Errorf("system = %+v", s)
	}
	if !s.BootedAt.Equal(time.Unix(1729670400, 0)) || s.SensorVersion != "0.1.8" || len(s.Addresses) != 2 || s.Arch == "" {
		t.Errorf("system = %+v", s)
	}

	// Values come from files the host writes: they are bounded, and missing files leave blanks.
	long := fstest.MapFS{"usr/lib/os-release": {Data: []byte("NAME=" + strings.Repeat("x", 5000) + "\nVERSION_ID=1\n")}}
	s = DetectSystem(long, "dev", nil)
	if len(s.OS) > maxSystemValue || s.Kernel != "" || s.CPUs != 0 {
		t.Errorf("bounded system = %d %q %d", len(s.OS), s.Kernel, s.CPUs)
	}
}
