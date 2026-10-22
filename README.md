# tripwatch

tripwatch rileva le modifiche non autorizzate sui server, qualunque cosa ci giri sopra. Controlla
ciò che un attaccante cambia per entrare e per restare: nuovi account privilegiati e chiavi SSH,
persistenze in cron, systemd e negli script di avvio, binari setuid e file immutabili, file di
sistema che non corrispondono più al loro pacchetto, processi avviati da eseguibili cancellati o
nascosti, connessioni in uscita inattese, codice applicativo modificato senza un deploy.

È indipendente dallo stack. Il nucleo non sa nulla di PHP, Python, Java o Rust: i controlli
specifici stanno in profili che si attivano quando la scoperta automatica trova la tecnologia
corrispondente. Funziona su host normali, host Docker, nodi Kubernetes e AWS Fargate.

## Come funziona

```
 server monitorato                                  macchina dedicata
┌──────────────────────────────┐                   ┌──────────────────────────────┐
│ tripwatch-sensor             │ firmati e in      │ tripwatch-verifier           │
│  raccoglie: stato, eventi,   │ catena            │  baseline e manifest         │
│  log                         │ ────────────────▶ │  regole, correlazione,       │
│  decide: niente              │ push su mTLS      │  allarmi                     │
└──────────────────────────────┘                   └──────────────────────────────┘
```

- **Il sensore osserva e basta.** È un binario Go statico senza dipendenze, quindi gira anche su
  distribuzioni vecchie o non aggiornate. Invia un battito ogni minuto e uno snapshot completo
  dello stato ogni ora; gli eventi critici in tempo reale sono nella roadmap.
- **Il verificatore decide, fuori dal server.** Baseline e manifest di build stanno dove un
  attaccante con root su un server monitorato non può riscriverli. Il verificatore non ha
  credenziali per entrare nei server: sono i sensori a inviare i dati.
- **Ogni messaggio è firmato e collegato al precedente.** Un messaggio perso, ripetuto o
  falsificato rompe la catena, e un sensore che tace è già un allarme.

Un file è legittimo solo se risale al gestore di pacchetti del sistema, a un manifest di deploy
firmato prodotto dalla build (confrontato con il lockfile: `composer.lock`, `package-lock.json`,
`poetry.lock`, `Cargo.lock`, `go.sum`, ...) oppure al digest di un'immagine container.

## Cosa raccoglie oggi il sensore

| Collector | Cosa riporta |
|---|---|
| `accounts` | utenti, UID, gruppi e stato della password (impostata, bloccata, vuota); l'hash della password non viene mai raccolto |
| `ssh` | impostazioni di sshd lette come le legge sshd (`Include` seguiti dove compaiono, primo valore vincente), blocchi `Match` riportati per intero, tutte le chiavi autorizzate di tutti gli account con fingerprint, commento e opzioni come `command=` |
| `sudoers` | regole di sudo, comprese le direttive `#include` e `#includedir` |
| `scheduled` | crontab di sistema e degli utenti, script di `cron.daily` e simili, job di `at` in attesa |
| `services` | unit systemd e drop-in di override, di sistema, transitorie e per utente, con i comandi `Exec*` e i link di attivazione; generator; `system.conf` e `user.conf` con le loro `DefaultEnvironment` |
| `hooks` | `ld.so.preload`, `rc.local`, `profile.d`, PAM, `update-motd.d`, hook dei gestori di pacchetti, file rc della shell di ogni account |
| `processes` | ogni processo con eseguibile (segnalato se cancellato dal disco), hash, cartella di lavoro, `LD_PRELOAD` e namespace; command line con password, token e credenziali redatti; i thread del kernel (flag del kernel) sono solo contati, i processi che ne imitano il nome vengono elencati |
| `sockets` | socket in ascolto, connessioni aperte e tentativi in uscita in corso, in ogni namespace di rete (container compresi), associati al processo |
| `packages` | file di sistema che non corrispondono più al database dei pacchetti (dpkg, apk), impronta del database stesso, eseguibili e symlink che nessun pacchetto possiede, elementi nascosti sotto `/usr` |
| `privileged` | scansione dell'intero filesystem (comprese le cartelle scrivibili da tutti in `/run` e `/dev/shm`) per binari setuid e setgid, file con capability Linux, file immutabili e append-only |
| `weblog` | log di accesso e di errore dei web server, letti in modo incrementale: eventi d'attacco raggruppati per regola, IP e path, statistiche su IP e destinazioni delle POST |
| `apps` | per WordPress, Magento, Drupal e Laravel: amministratori nel database, estensioni attive, script salvati in impostazioni e contenuti con i domini da cui caricano o verso cui inviano, impostazioni da sviluppo rimaste in produzione |
| `web` | inventario dei siti e delle applicazioni, e per ogni applicazione: albero di hash del codice, script nelle cartelle di upload, immagini poliglotte, firme di webshell, file nascosti, script che il web server esegue davvero |

Il sensore rileva anche l'ambiente in cui gira (host, container, Kubernetes, Fargate) e i runtime
di container presenti.

## Stack web

Il sensore legge le configurazioni di **nginx**, **Apache httpd** (layout Debian e Red Hat) e
**Caddy**: virtual host, document root, log, upstream e, per nginx, le `location` con lo stesso
ordine di selezione che usa nginx. Così sa quali script sono raggiungibili da internet e quali no:
uno strumento di amministrazione dimenticato fra gli entry point eseguibili viene segnalato come
raggiungibile, uno script caricato in una cartella protetta da `deny all` no.

Le applicazioni vengono riconosciute dalle loro impronte in `/var/www`, `/srv`, `/opt`, `/home`,
nei volumi Docker e nei document root dei siti. I profili coprono i principali CMS e framework
(WordPress, Drupal 7 e 8+, Magento, Laravel, Symfony, Django, Rails), le applicazioni Java, Rust,
Go, Node e Python, il PHP generico e i siti statici; per i framework principali viene letta anche
la versione installata. Aggiungere uno stack significa aggiungere un profilo: marker da cercare,
cartella pubblica, cartelle di upload e di dati, file da cui leggere la versione.

Per ogni applicazione il collector `web` produce:

- un **albero di hash** (Merkle) del codice, con l'hash delle cartelle fino al secondo livello:
  una riga cambiata in una dipendenza cambia l'hash della sua cartella e quello complessivo,
  mentre upload, cache e log ne restano fuori;
- **script nelle cartelle di upload** (`.php`, `.phtml`, `.phar`, `.jsp`, `.aspx`, doppie
  estensioni come `shell.php.png`) e **codice dentro file che non sono script**, come le sessioni
  serializzate usate dagli exploit di deserializzazione;
- **immagini poliglotte**: GIF, JPEG o PNG con codice dopo l'intestazione o in coda;
- **firme di webshell**: `eval` di payload decodificati, comandi eseguiti con input della
  richiesta, dropper che scrivono codice attraverso classi di libreria e altre, cercate dopo aver
  tolto i commenti dal sorgente; i blob codificati molto lunghi sono riportati a parte come
  indizio debole;
- **file nascosti** fra gli script e nelle cartelle di dati;
- i file di configurazione per cartella (`.htaccess`, `.user.ini`, `web.config`) con il loro hash, e
  un finding quando stanno in una cartella di upload, con l'indicazione delle direttive che fanno
  eseguire file come script;
- applicazioni annidate in una cartella di upload o di dati, e symlink sospetti.

`reachable` dice se un file sarebbe eseguito secondo la configurazione su disco. È un indizio, mai
un motivo per abbassare la gravità di un finding: chi controlla la configurazione può cambiarla.
Le configurazioni modificate dopo l'avvio del web server vengono segnalate, perché quella in
esecuzione può essere diversa.

Il collector è stato provato su applicazioni reali di stack diversi, fino a oltre 170.000 file per
applicazione. I falsi positivi rimasti sono file di librerie che contengono davvero quei pattern
(per esempio strumenti di analisi del codice che cercano proprio `preg_replace` con `/e`): la
baseline del verificatore li riconoscerà come noti dopo il primo snapshot.

## Applicazioni e database

Il collector `apps` legge la configurazione delle applicazioni riconosciute (`wp-config.php`,
`app/etc/env.php`, `settings.php` e `settings.local.php`, `.env`) e, se il database è MySQL o
MariaDB, lo interroga con sole `SELECT` e timeout di pochi secondi:

- gli **amministratori**, con email, data di creazione e ultimo accesso: un admin nuovo, con un
  dominio sconosciuto o con una data di creazione fuori sequenza è il segno tipico di un accesso
  persistente;
- gli **script salvati nel database**: opzioni e articoli di WordPress, `core_config_data`,
  blocchi e pagine CMS di Magento, contenuti di Drupal. Per ognuno vengono riportati i domini da
  cui gli script si caricano o a cui parlano: è lì che finiscono gli skimmer iniettati dal
  pannello o con un'injection;
- le **estensioni attive** (plugin, moduli) e gli URL del sito;
- le **impostazioni da sviluppo** rimaste in produzione: debug attivo, modalità sviluppatore,
  modifica dei file PHP dal pannello.

Il sensore si collega solo a destinazioni che può verificare, perché l'host del database viene
da un file che un attaccante può aver scritto e riceverebbe le credenziali vere:

- un socket Unix di proprietà dell'utente `mysql` o di root, in una directory che altri non
  possono scrivere, con un server database in esecuzione (`/tmp` è escluso);
- una porta di loopback su cui ascolta un processo `mysqld` o `mariadbd` di root o dell'utente
  `mysql`;
- un host indicato esplicitamente dall'operatore con `-app-db-hosts` (`db` oppure `db:3307`),
  per esempio il nome di un servizio Docker.

Ogni altro host viene riportato come avviso e non interrogato. Le credenziali vengono lette dai
file di configurazione o, quando l'applicazione usa `getenv()`, dall'ambiente dei processi di root
che avviano PHP (il master di FPM, l'init del container), mai da un processo dell'utente web.
Restano in memoria per la durata della connessione e lo snapshot riporta solo `database@host`. Se
il file di configurazione è scrivibile da un utente diverso da root, il profilo lo segnala: chi
può scriverlo può far leggere al sensore un database diverso. Ogni connessione ha un tetto di
byte ricevuti e le colonne lette sono troncate; il prefisso delle tabelle viene accettato solo se
è un identificatore semplice. Il collector si disattiva con `-app-db=false`.

## Log dei web server

Il collector `weblog` legge i log indicati dalle configurazioni di nginx, Apache e Caddy e quelli
nelle posizioni standard, riprendendo da dove si era fermato. I formati riconosciuti sono il
combined di nginx e Apache (anche con campi aggiuntivi in coda) e il JSON di Caddy. Le regole
cercano script richiesti nelle cartelle di upload, nomi di webshell note, comandi nei parametri,
POST verso file statici o verso endpoint che servono solo file, accesso a file sensibili (`.env`,
`.git`, backup), path traversal, SQL injection, sonde di injection, scanner noti, brute force sui
login pubblici e catene di exploit note, correlate per IP. La gravità di uno script nelle upload
non dipende dallo status HTTP, che decide lo script stesso.

Cosa finisce nello snapshot: IP, metodo, path, status, user agent e, per gli eventi, la richiesta
con i valori dei parametri **redatti** (resta solo il valore che costituisce la prova
dell'attacco; parametri con nomi sensibili come `token` o `password` sono sempre redatti). Il
testo scritto da chi ha fatto la richiesta sta in un campo `attacker_controlled`, da trattare come
dato e mai come istruzione. Righe, mappe e numero di eventi hanno un tetto: un flusso di richieste
da indirizzi e path sempre diversi non fa crescere la memoria. Gli eventi sono raggruppati per
script, come fa il web server (`/index.php/a` e `/index.php/b` sono un solo evento), e se un'ondata
di rumore satura l'elenco gli eventi gravi scartati vengono contati, ne restano path e indirizzo
dei primi, e il verificatore lo segnala come allarme. Se la parte di un log già letta
viene riscritta o troncata nello stesso file è un evento; ciò che viene scritto e poi cancellato
fra due letture, invece, non si può vedere. Le rotazioni (`name.1`, `dateext`, Caddy,
`copytruncate`) vengono riconosciute e la coda del file precedente viene letta; se non è
possibile, lo snapshot lo dice. Le posizioni avanzano solo dopo che lo snapshot è stato
consegnato.

## Cosa rileva, a confronto

<!-- bench:start -->
Su 29 scenari d'attacco riprodotti in un container Debian (commit `78d624e`), quanti ne rileva
ciascuno strumento con la configurazione di default:

![Scenari rilevati su 29: tripwatch 27, AIDE 24, rkhunter 4, debsums 1](bench/detection.svg)

| Categoria | Scenari | tripwatch | AIDE | rkhunter | debsums |
|---|:-:|:-:|:-:|:-:|:-:|
| Persistenza | 10 | 10 | 10 | 2 | 0 |
| Privilegi | 4 | 4 | 4 | 0 | 0 |
| Integrità del sistema | 5 | 5 | 5 | 1 | 1 |
| Processi e rete | 3 | 3 | 0 | 1 | 0 |
| Applicazioni web | 4 | 4 | 4 | 0 | 0 |
| Limiti: attacchi tra due controlli e trappole | 3 | 1 | 1 | 0 | 0 |
| **Totale** | **29** | **27** | **24** | **4** | **1** |

Rileva vuol dire che il dato sull'attacco compare nell'output dello strumento; per tripwatch il
giudizio resta al verificatore. Gli scenari della categoria "Limiti" (un dropper o una chiave SSH
che compaiono e spariscono tra due controlli) misurano il limite di chi confronta stati, tripwatch
compreso. Metodo, risultati per scenario, versioni e costo in [bench/RESULTS.md](bench/RESULTS.md).
<!-- bench:end -->

Dove AIDE e tripwatch vedono entrambi un file nuovo, AIDE dice solo che il file è comparso o è
cambiato; tripwatch dice anche di cosa si tratta: script nella cartella delle upload con la firma
della webshell, immagine con codice PHP, `.htaccess` che cambia il gestore dei file, codice
offuscato iniettato in un file dell'applicazione. Il costo di un controllo completo (tempo e
memoria di ciascuno strumento) è in [bench/RESULTS.md](bench/RESULTS.md).

## Modello di fiducia

Un attaccante con root su un server monitorato può fermarne il sensore o farlo mentire.
tripwatch non finge il contrario, ma punta a rendere visibili entrambe le cose. Già oggi:

- i messaggi sono firmati e collegati in catena: un messaggio perso, ripetuto o falsificato con
  una chiave diversa viene rilevato dal verificatore;
- il sensore legge i file in modo che l'utente del web server non possa bloccarlo né esaurirne la
  memoria: ogni apertura è non bloccante e controllata sul descrittore (FIFO e dispositivi vengono
  rifiutati), le letture hanno un tetto, i file enormi vengono letti solo in testa e in coda, ogni
  collector ha un timeout e, su Linux, i symlink si risolvono dentro la root osservata.

- il battito scopre un sensore fermo entro pochi minuti, e un sensore che manda battiti ma non
  più snapshot solleva un allarme a sé; ogni avvio del sensore arriva come evento firmato e
  ogni pausa tra due battiti oltre i 100 secondi diventa un allarme, così anche un arresto
  o una sospensione più brevi della soglia di silenzio lasciano traccia;
- gli allarmi critici e alti non si chiudono da soli quando la condizione sparisce: un server
  compromesso potrebbe ripulire e far tacere i propri allarmi, quindi li chiude una persona.

Arriveranno:

- gli eventi di escalation dei privilegi spediti appena accadono, prima che l'attaccante possa
  agire sul sensore (fino ad allora ciò che accade fra due snapshot, come un processo che dura
  pochi secondi, non viene visto);
- i controlli che non girano sul server (pagine scaricate dall'esterno, API del cloud provider,
  canary token, snapshot del disco verificati a freddo), che non si possono silenziare da lì.

Un attaccante con root può copiare la chiave di firma e continuare la catena con dati credibili:
contro questo servono i controlli esterni e, in prospettiva, una chiave legata all'hardware.

La maggior parte delle compromissioni web passa settimane o mesi con l'utente del web server
prima di arrivare a root. In quella fase l'attaccante non ha i permessi per fermare il sensore o
modificarne i file, e i file che può creare non bastano a bloccarlo.

Il design completo è in [docs/architecture.md](docs/architecture.md).

## Limiti noti

- Lo storage dei container (`/var/lib/docker` e simili) non viene ancora esaminato: arriverà con
  il collector dei container, che confronterà i container in esecuzione con le loro immagini.
- Il sensore produce snapshot: ciò che nasce e sparisce fra due esecuzioni non si vede finché non
  ci sarà il flusso di eventi in tempo reale.
- Il database dei pacchetti sull'host fa da riferimento: con root un attaccante può aggiornare un
  checksum per coprire un binario sostituito. La sua impronta cambia e il verificatore lo vedrà
  fra due snapshot; il confronto con i metadati firmati dei repository è una scelta ancora da
  fare.
- Il sensore fuori da Linux serve solo allo sviluppo: il confinamento dei symlink si basa su
  interfacce Linux.
- Con un battito al minuto, un sensore sospeso per meno di 100 secondi non si distingue da un
  ritardo di rete e non dà allarme; pause più lunghe sì, anche se poi i battiti riprendono.
- Chi accede alla console da un browser mai usato prima, mentre qualcuno sta tentando password
  sulla sua stessa email, aspetta in fila con quei tentativi (al massimo 25 secondi, poi riprova);
  dai browser già usati l'accesso non viene mai rallentato.

## Build

Serve Go (la versione è in `go.mod`).

```sh
make build   # binari per questa macchina in bin/
make dist    # binari Linux statici (amd64, arm64) in dist/
make test    # test con il race detector
make cover   # test con la soglia di coverage
make lint    # go vet e golangci-lint
```

## Verificatore

Il verificatore gira su una macchina dedicata, fuori dai server monitorati, come stack
`docker-compose`. Espone due porte:

- `8443`, l'ingresso dei sensori: TLS 1.3 con certificato client obbligatorio, firmato dalla CA
  privata del verificatore. Va raggiunto dai server monitorati.
- `8080`, l'interfaccia web in HTTP, pubblicata solo su `127.0.0.1`: va esposta dietro un reverse
  proxy HTTPS (nginx, Caddy, Traefik) o raggiunta con un tunnel SSH.

```sh
cd deploy/verifier
cp .env.example .env      # nomi, URL pubblici, primo utente, SMTP
docker compose up -d --build
```

Al primo avvio il verificatore crea la CA, il certificato del server per i nomi in
`TRIPWATCH_HOSTNAMES` e il primo utente da `TRIPWATCH_ADMIN_EMAIL` e `TRIPWATCH_ADMIN_PASSWORD`
(almeno 12 caratteri; dopo il primo accesso la password si può togliere dal file). Tutto lo stato
(database SQLite, CA, baseline) sta nel volume `data`: va incluso nei backup, perché perderlo
significa registrare di nuovo ogni server. Il container gira senza root, con filesystem in sola
lettura e nessuna capability.

Lo spazio cresce con il numero di server, non con il tempo. Il verificatore conserva tutti gli
snapshot delle ultime 48 ore; poi, fino a 30 giorni, l'ultimo di ogni giorno e quelli che
mostrano un cambiamento insieme al precedente; il primo di ogni server per sempre. Con snapshot
compressi da qualche centinaio di KB si arriva a circa 40 MB per server, quindi 50 server stanno
in un paio di GB; battiti e allarmi pesano poco. Un server che supera 1 GB di snapshot in un
giorno, o 4 GB conservati in tutto, resta vivo per il verificatore, ma gli snapshot oltre la quota
non vengono conservati e compare un allarme; allo stesso modo un server non può tenere aperti più di 2000 allarmi.

Altri utenti o una nuova password:

```sh
docker compose exec verifier /tripwatch-verifier user -email collega@example.net
```

### Interfaccia

- **Panoramica.** Un quadro da sala controllo: tutto è grigio finché qualcosa devia. In alto i
  contatori (critici, muti, alti, in carico, ognuno con l'età del più vecchio); sotto, la tabella
  dei server con chi devia in cima e il più vecchio per primo; poi gli allarmi da gestire. Su
  schermi larghi, a lato, il dettaglio dell'allarme da guardare per primo con le sue azioni;
  cliccando un altro allarme (anche dalla pagina Allarmi) il pannello mostra quello, con il link
  per aprirne il dettaglio. Ogni gravità ha una forma oltre al colore (rombo muto, triangolo
  critico, quadrato alto, cerchio medio, cerchio vuoto basso), e un server muto è un segno
  presente con la riga tratteggiata, non una riga spenta.
- **Server.** Stato, tutti gli allarmi, i silenzi degli ultimi 7 giorni con la durata, gli ultimi
  snapshot ricevuti, la revoca.
- **Allarmi.** Da gestire, presi in carico, risolti. Ogni allarme si può prendere in carico e
  risolvere; il dettaglio mostra il testo raccolto dal server come dato, senza interpretarlo.
- **Registra server.** Genera il token monouso con il comando da eseguire sul server, oppure il
  pacchetto con le chiavi da scaricare una sola volta; il verificatore non conserva né l'uno né
  l'altro.

L'interfaccia è in italiano, con tema chiaro e scuro (segue il sistema, oppure si sceglie dal
menu), si aggiorna da sola ogni minuto e funziona anche da telefono. Le pagine non eseguono script
o stili inline (Content Security Policy rigida), i moduli sono protetti da token CSRF e i
tentativi di accesso per lo stesso indirizzo email passano uno alla volta, con un ritardo che
cresce dopo cinque errori fino a 15 secondi, da qualunque indirizzo arrivino: indovinare la
password diventa lentissimo anche provando in parallelo. Il browser con cui si è già entrati ha una
corsia sua, che nessun attacco rallenta, quindi l'utente non resta mai chiuso fuori.

### Email

Con `TRIPWATCH_SMTP_HOST` impostato, gli allarmi critici e alti arrivano per email, raggruppati in
un messaggio per giro, con il link al dettaglio. Se l'invio fallisce, l'interfaccia lo mostra come
allarme del verificatore.

## Esecuzione del sensore

Il modo consigliato è il token: dall'interfaccia ("Registra server") si sceglie il nome del server
e si ottiene un comando da eseguire sul server, come root:

```sh
echo 'tw1....' | tripwatch-sensor enroll -token-file - && systemctl enable --now tripwatch-sensor
```

Il sensore genera da sé chiave TLS e chiave di firma, verifica che il verificatore sia quello
giusto confrontando la sua CA con l'impronta contenuta nel token, e solo allora invia il segreto
e le chiavi pubbliche; le chiavi private non lasciano mai il server. Il token vale un'ora e una
volta sola, e il verificatore ne conserva solo l'hash. Il token passa sullo standard input
perché gli argomenti di un processo li legge qualunque utente del server; ogni registrazione
solleva un allarme, e un token presentato di nuovo dopo l'uso ne solleva uno critico, perché
vuol dire che qualcuno ne ha una copia. Anche al rinnovo del certificato la chiave nuova nasce
sul server.

In alternativa il verificatore genera un pacchetto con le chiavi già dentro, dall'interfaccia o
da riga di comando:

```sh
(umask 077; docker compose exec -T verifier /tripwatch-verifier enroll -host web-01 -out - > web-01.json)
```

Il pacchetto va copiato sul server e il servizio avviato:

```sh
sudo install -o root -g root -m 600 web-01.json /etc/tripwatch/bundle.json
sudo systemctl enable --now tripwatch-sensor
```

Il sensore rifiuta un pacchetto che non appartiene al suo utente, leggibile da altri utenti o con
un indirizzo del verificatore non `https`. Il certificato client dura due anni e il sensore lo rinnova da
solo negli ultimi due mesi, senza riavvio e senza toccare il pacchetto. Lo stato fra un avvio e l'altro
(posizione nella catena, busta in attesa di conferma, posizioni nei log) sta in `-state-dir`
(predefinito `/var/lib/tripwatch`); ogni busta viene salvata prima di essere spedita e rispedita
identica se la conferma si perde.

Senza `-bundle` il sensore stampa uno snapshot in JSON ed esce, utile per vedere cosa raccoglie:

```sh
sudo ./tripwatch-sensor > snapshot.json
```

Su un nodo Kubernetes si monta la root dell'host nel pod e si indica al sensore dove si trova:

```sh
tripwatch-sensor -root /host
```

Una unit systemd con le restrizioni di sicurezza è in [deploy/systemd](deploy/systemd).

## Roadmap

1. Eventi in tempo reale via eBPF o auditd, spediti appena accadono.
2. Installazione senza toolchain: pacchetti `.deb`, `.rpm` e `.apk` firmati e repository APT/YUM
   (la registrazione con token monouso c'è già), immagine e chart Helm per il DaemonSet; il
   verificatore confronta il binario in esecuzione con quello della versione pubblicata.
3. Manifest di deploy firmati prodotti dalla build e confrontati con il lockfile.
4. Container: differenze dei container in esecuzione rispetto all'immagine, container privilegiati.
5. Kubernetes e AWS: DaemonSet, audit log, CloudTrail, VPC Flow Logs.
6. Controlli dall'esterno e canary token.
7. Verifica dei pacchetti rpm.
8. Database PostgreSQL per i profili applicativi (Django, Rails, Drupal su PostgreSQL).

## Stato

Sviluppo iniziale, utilizzabile end-to-end. Sono implementati e testati il protocollo delle
buste, la scoperta dell'ambiente e dello stack web, i collector di sistema, web, dei log e delle
applicazioni, il sensore come servizio, il verificatore con regole, allarmi, email e interfaccia
web. Il prossimo passo sono gli eventi in tempo reale.
