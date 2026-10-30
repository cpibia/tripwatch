# category: noise
# title: Deploy that rewrites the site's code with a new release
# indicator: /var/www/wp/wp-includes
for f in /var/www/wp/index.php /var/www/wp/wp-includes/*.php /var/www/wp/wp-content/index.php; do
  printf '%s\n// release 2026.10.30\n' "$(cat "$f")" >"$f.new" && mv "$f.new" "$f"
done
sed -i "s/\\\$wp_version = '[^']*'/\$wp_version = '6.6.3'/" /var/www/wp/wp-includes/version.php
chown -R www-data:www-data /var/www/wp
