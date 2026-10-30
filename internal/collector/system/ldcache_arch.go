package system

import "runtime"

// nativeLibcFlags are the flags ldconfig gives a libc6 library of the architecture the sensor
// was built for (FLAG_ELF_LIBC6 with the architecture's bits from glibc's ldconfig.h); 0 where
// the sensor is not built.
var nativeLibcFlags = map[string]uint32{"amd64": 0x0303, "arm64": 0x0a03}[runtime.GOARCH]
