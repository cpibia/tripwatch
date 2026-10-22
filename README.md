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
  distribuzioni vecchie o non aggiornate. Invia gli eventi critici appena accadono, uno snapshot
  completo a intervalli regolari e un battito che dimostra che è vivo.
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
| `ssh` | impostazioni di sshd e tutte le chiavi autorizzate di tutti gli account, con fingerprint, commento e opzioni come `command=` |
| `sudoers` | regole di sudo, comprese le direttive `#include` e `#includedir` |
| `scheduled` | crontab di sistema e degli utenti, script di `cron.daily` e simili, job di `at` in attesa |
| `services` | unit systemd e drop-in di override, di sistema e per utente, con i comandi `Exec*` e i link di attivazione |
| `hooks` | `ld.so.preload`, `rc.local`, `profile.d`, PAM, `update-motd.d`, hook dei gestori di pacchetti, file rc della shell di ogni account |
| `processes` | ogni processo con eseguibile (segnalato se cancellato dal disco), hash, cartella di lavoro e `LD_PRELOAD`; i thread del kernel sono solo contati, i processi che ne imitano il nome vengono elencati |
| `sockets` | socket in ascolto, connessioni aperte e tentativi in uscita in corso, in ogni namespace di rete (container compresi), associati al processo |
| `packages` | file di sistema che non corrispondono più al database dei pacchetti (dpkg, apk), eseguibili che nessun pacchetto possiede, elementi nascosti sotto `/usr` |
| `privileged` | scansione dell'intero filesystem per binari setuid e setgid, file con capability Linux, file immutabili e append-only |
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
- i file di configurazione per cartella (`.htaccess`, `.user.ini`, `web.config`) con il loro hash.

Il collector è stato provato su applicazioni reali di stack diversi, fino a oltre 170.000 file per
applicazione. I falsi positivi rimasti sono file di librerie che contengono davvero quei pattern
(per esempio strumenti di analisi del codice che cercano proprio `preg_replace` con `/e`): la
baseline del verificatore li riconoscerà come noti dopo il primo snapshot.

## Modello di fiducia

Un attaccante con root su un server monitorato può fermarne il sensore o farlo mentire.
tripwatch non finge il contrario, ma rende visibili entrambe le cose:

- un sensore fermo viene scoperto entro pochi minuti dal battito mancante;
- gli eventi di escalation dei privilegi partono prima che l'attaccante possa agire sul sensore;
- falsificare i dati richiede di rubare la chiave di firma e continuare la catena in modo
  credibile;
- i controlli che non girano sul server (pagine scaricate dall'esterno, API del cloud provider,
  canary token, snapshot del disco verificati a freddo) non si possono silenziare da lì.

La maggior parte delle compromissioni web passa settimane o mesi con l'utente del web server
prima di arrivare a root. In quella fase l'attaccante non ha i permessi per fermare il sensore o
modificarne i file.

Il design completo è in [docs/architecture.md](docs/architecture.md).

## Build

Serve Go (la versione è in `go.mod`).

```sh
make build   # binari per questa macchina in bin/
make dist    # binari Linux statici (amd64, arm64) in dist/
make test    # test con il race detector
make cover   # test con la soglia di coverage
make lint    # go vet e golangci-lint
```

## Esecuzione

Finché il verificatore non è pronto, il sensore stampa lo snapshot in JSON:

```sh
sudo ./tripwatch-sensor > snapshot.json
```

Su un nodo Kubernetes si monta la root dell'host nel pod e si indica al sensore dove si trova:

```sh
tripwatch-sensor -root /host
```

Una unit systemd con le restrizioni di sicurezza è in [deploy/systemd](deploy/systemd).

## Roadmap

1. Log dei web server: lettura incrementale dei log trovati dalla scoperta, formato unico per
   nginx, Apache e Caddy, regole sugli attacchi (upload seguito da esecuzione, POST verso script
   in cartelle statiche, scanner, catene di exploit note di CMS e framework).
2. Profili applicativi: amministratori nel database, configurazioni salvate nel database che
   iniettano script nelle pagine, moduli e plugin attivi.
3. Verificatore come stack `docker-compose`: interfaccia web curata con l'elenco dei server, lo
   stato di ciascuno, gli allarmi e il dettaglio dei finding; notifiche email; ricezione su mTLS;
   baseline, confronto e regole.
4. Trasporto nel sensore: snapshot e battiti dentro buste firmate, eventi in tempo reale via eBPF
   o auditd.
5. Manifest di deploy firmati prodotti dalla build e confrontati con il lockfile.
6. Container: differenze dei container in esecuzione rispetto all'immagine, container privilegiati.
7. Kubernetes e AWS: DaemonSet, audit log, CloudTrail, VPC Flow Logs.
8. Controlli dall'esterno e canary token.
9. Verifica dei pacchetti rpm.

## Stato

Sviluppo iniziale. Sono implementati e testati il protocollo delle buste, la scoperta
dell'ambiente e dello stack web, i collector di sistema e il collector web. In corso: log dei web
server; poi profili applicativi e verificatore.
