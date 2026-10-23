package watch

import "testing"

// Homes that are system directories are not watched; real ones are, with their .ssh.
func TestTargetsHomes(t *testing.T) {
	dirs := map[string]bool{}
	for _, tg := range Targets([]Home{{"bin", "/bin"}, {"daemon", "/usr/sbin"}, {"nobody", "/nonexistent"}, {"alice", "/home/alice"}, {"www-data", "/var/www"}}, []string{"/var/www/site/uploads", "relative"}) {
		dirs[tg.Dir] = true
	}
	for _, d := range []string{"/bin", "/usr/sbin", "/nonexistent", "relative"} {
		if dirs[d] {
			t.Errorf("%s is watched", d)
		}
	}
	for _, d := range []string{"/home/alice", "/home/alice/.ssh", "/var/www", "/var/www/.ssh", "/var/www/site/uploads", "/etc/sudoers.d"} {
		if !dirs[d] {
			t.Errorf("%s is not watched", d)
		}
	}
}
