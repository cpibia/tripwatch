# Benchmark di rilevamento

Commit `78d624e`, 2026-10-22, container Debian GNU/Linux 12 (bookworm) su arm64. Strumenti di confronto: AIDE 0.18.3, rkhunter 1.4.6-11, debsums 3.0.2.1,
con la configurazione di default dei pacchetti Debian. Si rigenera con `bench/run.sh`.

## Metodo

Ogni scenario parte da un container pulito, uguale per tutti: una Debian con un sito WordPress, su cui
ogni strumento ha già preso la sua baseline. Lo scenario applica l'attacco, poi tutti gli strumenti
girano una volta. Uno strumento **rileva** lo scenario quando nel suo output le righe che citano
l'artefatto dell'attacco (un percorso, il commento di una chiave, una porta) sono diverse da quelle
della baseline: qualcosa di nuovo è comparso o qualcosa di noto è cambiato. Per tripwatch si confrontano
gli oggetti JSON dello snapshot che contengono l'artefatto: il giudizio finale spetta al verificatore,
qui si misura se il dato arriva. **Bloccato** vuol dire che lo strumento non ha finito entro 900 s.

Lo scenario di controllo, senza attacco, non produce differenze per nessuno strumento.

## Risultati per scenario

### Persistenza

| Scenario | tripwatch | AIDE | rkhunter | debsums |
|---|:-:|:-:|:-:|:-:|
| Chiave SSH aggiunta a root | ✅ | ✅ | ❌ | ❌ |
| Nuovo account con UID 0 | ✅ | ✅ | ✅ | ❌ |
| Regola sudo NOPASSWD per www-data | ✅ | ✅ | ❌ | ❌ |
| Job in /etc/cron.d | ✅ | ✅ | ❌ | ❌ |
| Crontab dell'utente web | ✅ | ✅ | ❌ | ❌ |
| Servizio systemd abilitato | ✅ | ✅ | ❌ | ❌ |
| Generator systemd (gira da root a ogni boot) | ✅ | ✅ | ❌ | ❌ |
| Libreria iniettata con /etc/ld.so.preload | ✅ | ✅ | ✅ | ❌ |
| Script di login in /etc/profile.d | ✅ | ✅ | ❌ | ❌ |
| Riga aggiunta al .bashrc di root | ✅ | ✅ | ❌ | ❌ |

### Privilegi

| Scenario | tripwatch | AIDE | rkhunter | debsums |
|---|:-:|:-:|:-:|:-:|
| Shell setuid in /var/tmp | ✅ | ✅ | ❌ | ❌ |
| Shell setuid in /run/lock (tmpfs scrivibile da tutti) | ✅ | ✅ | ❌ | ❌ |
| Capability cap_setuid su una copia di un binario | ✅ | ✅ | ❌ | ❌ |
| Backdoor protetta con chattr +i | ✅ | ✅ | ❌ | ❌ |

### Integrità del sistema

| Scenario | tripwatch | AIDE | rkhunter | debsums |
|---|:-:|:-:|:-:|:-:|
| Binario di un pacchetto modificato | ✅ | ✅ | ❌ | ✅ |
| PermitRootLogin abilitato in sshd_config | ✅ | ✅ | ❌ | ❌ |
| Eseguibile estraneo ai pacchetti in /usr/local/bin | ✅ | ✅ | ❌ | ❌ |
| Link che dirotta sudo da /usr/local/bin | ✅ | ✅ | ✅ | ❌ |
| Directory nascosta sotto /usr/lib | ✅ | ✅ | ❌ | ❌ |

### Processi e rete

| Scenario | tripwatch | AIDE | rkhunter | debsums |
|---|:-:|:-:|:-:|:-:|
| Processo avviato da un eseguibile poi cancellato | ✅ | ❌ | ❌ | ❌ |
| Backdoor in ascolto sulla porta 31337 | ✅ | ❌ | ✅ | ❌ |
| Processo con LD_PRELOAD nell'ambiente | ✅ | ❌ | ❌ | ❌ |

### Applicazioni web

| Scenario | tripwatch | AIDE | rkhunter | debsums |
|---|:-:|:-:|:-:|:-:|
| Webshell nelle upload di WordPress | ✅ | ✅ | ❌ | ❌ |
| Immagine GIF con codice PHP in coda | ✅ | ✅ | ❌ | ❌ |
| Backdoor iniettata in un file PHP esistente | ✅ | ✅ | ❌ | ❌ |
| .htaccess che fa eseguire le immagini come PHP | ✅ | ✅ | ❌ | ❌ |

### Limiti: attacchi tra due controlli e trappole

| Scenario | tripwatch | AIDE | rkhunter | debsums |
|---|:-:|:-:|:-:|:-:|
| Dropper eseguito e cancellato tra due controlli | ❌ | ❌ | ❌ | ❌ |
| Chiave SSH aggiunta, usata e rimossa tra due controlli | ❌ | ❌ | ❌ | ❌ |
| FIFO al posto di authorized_keys dell'utente web | ✅ | ✅ | ❌ | ❌ |

## Costo di un controllo completo

Misurato sullo scenario di controllo, nello stesso container.

| Strumento | Tempo | Memoria massima |
|---|--:|--:|
| tripwatch | 1.1 s | 26 MB |
| AIDE | 19.0 s | 34 MB |
| rkhunter | 83.4 s | 11 MB |
| debsums | 1.3 s | 12 MB |
