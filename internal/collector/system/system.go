package system

import "github.com/cpibia/tripwatch/internal/collector"

// All returns the system collectors with their default settings.
func All() []collector.Collector {
	return []collector.Collector{
		Accounts{},
		SSH{},
		Sudoers{},
		Scheduled{},
		Services{},
		Hooks{},
		Processes{},
		Sockets{},
		Packages{},
		Privileged{Skip: DefaultSkip, Extra: DefaultExtra},
	}
}
