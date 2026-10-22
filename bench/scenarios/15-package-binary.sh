# category: integrity
# title: Binario di un pacchetto modificato
# indicator: /usr/bin/pinky
printf '\x00bench' >>/usr/bin/pinky
