package discovery

import (
	"fmt"
	"slices"

	"github.com/cpibia/tripwatch/internal/collector"
)

// configBudget bounds the parsing of one web server configuration: how many files and bytes
// it may read in total, and no file may include itself through a chain of includes. The same
// snippet included by several servers is fine; only cycles and runaway fan-out are cut.
type configBudget struct {
	server   string
	files    []string
	parsed   int
	bytes    int
	chain    []string
	exceeded bool
}

func newConfigBudget(server string) *configBudget {
	return &configBudget{server: server}
}

func (b *configBudget) enter(name string, issues *collector.Issues) bool {
	if slices.Contains(b.chain, name) {
		*issues = append(*issues, fmt.Sprintf("%s: /%s includes itself, cycle ignored", b.server, name))
		return false
	}
	if b.parsed >= maxConfigFiles {
		b.fail(issues, fmt.Sprintf("more than %d configuration files", maxConfigFiles))
		return false
	}
	b.parsed++
	b.chain = append(b.chain, name)
	if !slices.Contains(b.files, name) {
		b.files = append(b.files, name)
	}
	return true
}

func (b *configBudget) leave(string) {
	b.chain = b.chain[:len(b.chain)-1]
}

func (b *configBudget) consume(n int, issues *collector.Issues) bool {
	b.bytes += n
	if b.bytes > maxConfigBytes {
		b.fail(issues, fmt.Sprintf("more than %d bytes of configuration", maxConfigBytes))
		return false
	}
	return true
}

// fail reports the budget once: an include fan-out would otherwise add an issue per file.
func (b *configBudget) fail(issues *collector.Issues, reason string) {
	if !b.exceeded {
		*issues = append(*issues, fmt.Sprintf("%s: parsing stopped after %s (include fan-out or a hostile configuration)", b.server, reason))
		b.exceeded = true
	}
}
