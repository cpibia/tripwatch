package analyze

import (
	"github.com/cpibia/tripwatch/internal/collector"
	"github.com/cpibia/tripwatch/internal/collector/apps"
	"github.com/cpibia/tripwatch/internal/collector/system"
)

// Short names for the element types the rules compare.
type (
	accountT = system.Account
	keyT     = system.AuthorizedKey
	sudoersT = system.SudoersFile
	cronT    = system.CronTable
	unitT    = system.Unit
	socketT  = system.Socket
	fileT    = collector.File
	adminT   = apps.Admin
)
