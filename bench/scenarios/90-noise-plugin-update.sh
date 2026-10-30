# category: noise
# title: Update of a WordPress plugin, its version and sixty files rewritten
# indicator: wp-content/plugins/demo-gallery
p=/var/www/wp/wp-content/plugins/demo-gallery
sed -i 's/1\.0\.0/1.1.0/' "$p/demo-gallery.php" "$p/readme.txt"
for f in "$p"/includes/part-*.php; do printf '<?php\n// 1.1.0\n%s\n' "$(tail -n +2 "$f")" >"$f"; done
for f in "$p"/assets/js/*.js; do printf '/* 1.1.0 */%s\n' "$(cat "$f")" >"$f"; done
chown -R www-data:www-data "$p"
