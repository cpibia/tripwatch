# Architettura

tripwatch rileva le modifiche non autorizzate sui server: nuovi utenti privilegiati, chiavi SSH,
persistenze (cron, systemd, binari SUID, file immutabili), codice applicativo modificato senza un
deploy dietro, webshell, skimmer e pattern di attacco nei log dei web server. È indipendente dallo
stack: il nucleo non sa nulla di linguaggi o framework, e tutto ciò che è specifico sta in profili
che si attivano quando la scoperta automatica trova la tecnologia corrispondente.

## Componenti

**Sensore** (`cmd/tripwatch-sensor`): un binario statico su ogni macchina monitorata. Osserva e
riferisce, non decide mai. Oggi produce uno snapshot completo dello stato a ogni esecuzione. Con
il trasporto, gli eventi critici (utenti, chiavi, sudoers, setuid, nuove unit e righe di cron,
moduli del kernel) verranno inviati appena accadono e un battito dimostrerà che il sensore è vivo.

**Verificatore** (`cmd/tripwatch-verifier`): gira su una macchina dedicata. Tiene baseline e
manifest di build fuori dai server monitorati, confronta, applica le regole e genera gli allarmi.
Non ha credenziali per le macchine monitorate: sono i sensori a inviargli i dati.

## Fonti di verità

Un file è legittimo solo se risale a una di queste fonti:

1. il gestore di pacchetti del sistema (checksum di dpkg, rpm, apk);
2. un manifest di deploy firmato prodotto dalla build, per qualsiasi linguaggio, confrontato con
   il lockfile (`composer.lock`, `package-lock.json`, `poetry.lock`, `Cargo.lock`, `go.sum`, ...);
3. il digest di un'immagine container: tutto ciò che in un container in esecuzione differisce
   dall'immagine è una deriva.

## Modello di fiducia

Un attaccante con root su un server monitorato può fermarne il sensore o fingersi lui. tripwatch
non cerca di impedirlo, lo rende visibile:

- le buste sono firmate e collegate in una catena di hash (`internal/protocol`): messaggi persi,
  ripetuti o biforcati vengono rilevati, e un battito mancante è un allarme;
- gli eventi di escalation dei privilegi partono prima che l'attaccante possa agire sul sensore;
- i controlli che non girano sul server (pagine scaricate dall'esterno, API del provider, canary
  token, snapshot del disco verificati a freddo) non si possono silenziare da lì.

## Lettura sicura dei file

Il sensore gira come root ma legge file che un utente non privilegiato può creare o sostituire.
Tutti i collector passano da un'unica vista del filesystem (`rootFS` in `internal/collector`):

- su Linux il percorso viene prima risolto con `O_PATH`, che non apre il file: un dispositivo o
  una FIFO non subiscono nessuna operazione. `fstat` sul descrittore ne legge il tipo e solo file
  regolari e directory vengono riaperti in lettura, attraverso `/proc/self/fd`, sullo stesso
  inode; la lettura è comunque `O_NONBLOCK|O_NOCTTY`;
- quando la root osservata non è `/` (DaemonSet con `-root /host`) i symlink si risolvono dentro
  la root, come per l'host e non nel container del sensore: con `openat2` e `RESOLVE_IN_ROOT` se
  il kernel lo offre, altrimenti (kernel vecchio, `openat2` vietato da seccomp) con un resolver in
  userspace che segue i link componente per componente e apre l'ultimo con `O_NOFOLLOW`. In quel
  caso lo snapshot riporta un avviso (`warnings`), perché il resolver in userspace è esposto a
  race che `openat2` non ha. `/proc` fa eccezione: i suoi link speciali servono al collector dei
  processi;
- `Lstat` e `ReadLink` risolvono la directory padre nello stesso modo e leggono l'ultimo
  componente attraverso il suo descrittore, così un link intermedio non porta fuori dalla root;
- `ReadFile` rifiuta i file oltre `MaxReadSize` con un errore, mai con un risultato troncato;
  `ReadDir` si ferma oltre un numero massimo di voci e lo dice;
- l'hash si calcola fino a `MaxHashSize`; oltre, il file viene riportato senza hash con un errore
  esplicito e il collector web usa come impronta dimensione, ctime e inode (l'mtime si può
  riportare indietro senza privilegi, il ctime no) leggendo solo testa e coda del file;
- ogni collector gira con un timeout (`collector.Timeout`): uno bloccato non ferma gli altri.

## Stack web

La scoperta (`internal/discovery`) legge le configurazioni di nginx, Apache e Caddy seguendo gli
include, risolve le variabili (`set $MAGE_ROOT` di nginx, `envvars` di Apache) e produce un
elenco di siti con document root, log e upstream. Per nginx conserva l'albero delle `location` e
lo interroga con lo stesso ordine di nginx (corrispondenza esatta, prefisso più lungo, `^~`,
regex nell'ordine del file, regex annidate prima di quelle esterne): `Site.Executes(uri)` dice se
una richiesta arriva all'interprete. Per Apache e Caddy basta sapere se c'è un handler PHP.

Le applicazioni si riconoscono con dei profili: marker che devono esistere, cartella pubblica,
cartelle di upload, cartelle di dati e file da cui leggere la versione. I profili specifici
vengono prima di quelli generici, e le radici dei siti si provano dalla più esterna alla più
interna, così `pub` di Magento non viene scambiata per un'applicazione PHP a sé.

Il collector `web` percorre ogni applicazione una sola volta. Ogni file viene letto una volta:
lo stesso contenuto serve per l'hash e per i controlli. L'albero di hash copre il codice e lascia
fuori le cartelle di dati, che cambiano da sole; le cartelle di dati vengono comunque ispezionate.
I nomi generici di upload (`uploads`, `media`, `files`...) valgono solo sotto la radice
dell'applicazione o della web root e solo se il profilo non indica dove vanno gli upload: più in
basso sono normali cartelle di codice.

## Struttura dei package

| Package | Ruolo |
|---|---|
| `internal/protocol` | formato delle buste, firma, verifica della catena |
| `internal/discovery` | ambiente di esecuzione, runtime di container, siti di nginx, Apache e Caddy con il loro routing, applicazioni e runtime attivi |
| `internal/collector` | contratto dei collector, snapshot, descrizione dei file (hash, proprietario, flag dell'inode) |
| `internal/collector/system` | account, SSH, sudoers, cron e at, unit systemd, hook di avvio, processi, socket, verifica dei pacchetti, file privilegiati |
| `internal/collector/web` | per ogni applicazione: albero di hash del codice, upload, poliglotte, firme di webshell, file nascosti, script raggiungibili |
| `internal/buildinfo` | versione inserita al momento della build |

Previsti: `internal/collector/weblog` (log dei web server), profili applicativi con accesso al
database, `internal/verifier/...` (ricezione su mTLS, archivio, regole, allarmi, interfaccia web,
email) distribuito come stack `docker-compose`, `internal/collector/...` per i container,
`deploy/` (systemd, DaemonSet Kubernetes).
