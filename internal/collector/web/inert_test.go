package web

import "testing"

// What the scan withdraws from an upload directory is what the real-time rules let pass.
func TestInertInUploads(t *testing.T) {
	twig := "<?php\n\nuse Twig\\Environment;\n\nclass __TwigTemplate_x extends Template {}\n"
	for _, c := range []struct {
		name, content string
		want          bool
	}{
		{"/srv/up/plugin/debug-log.php", "<?php exit; ?>\n[2026-11-06] failed\n", true},
		{"/srv/up/plugin/debug-log.php", "<?php exit; ?>\n<?php system($_GET['c']);", false},
		{"/srv/up/a.php", "<?php system($_GET['c']);", false},
		{"/srv/up/silence.php", "Silence is golden.", true},
		{"/srv/up/index.php", "<?php // Silence is golden.", true},
		{"/var/www/s/sites/default/files/php/twig/abc_x/t.php", twig, true},
		{"/var/www/s/sites/default/files/php/twig/abc_x/t.php", twig + "eval($_POST['c']);", false},
		{"/srv/up/t.php", twig, false},
		{"/srv/up/.htaccess", "<IfModule mod_authz_core.c>\n  Require all denied\n</IfModule>\n", true},
		{"/srv/up/.htaccess", "AddHandler application/x-httpd-php .jpg\n", false},
		{"/srv/up/x.pl", "print 1;", false},
	} {
		if got := InertInUploads(c.name, []byte(c.content)); got != c.want {
			t.Errorf("%s %.40q: %v, want %v", c.name, c.content, got, c.want)
		}
	}
}
