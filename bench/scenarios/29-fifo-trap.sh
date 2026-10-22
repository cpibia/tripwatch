# category: limits
# title: FIFO al posto di authorized_keys dell'utente web
# indicator: var/www/.ssh/authorized_keys
mkdir -p /var/www/.ssh
mkfifo /var/www/.ssh/authorized_keys
chown -R www-data:www-data /var/www/.ssh
