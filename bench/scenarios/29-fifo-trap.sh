# category: limits
# title: FIFO in place of the web user's authorized_keys
# indicator: var/www/.ssh/authorized_keys
mkdir -p /var/www/.ssh
mkfifo /var/www/.ssh/authorized_keys
chown -R www-data:www-data /var/www/.ssh
