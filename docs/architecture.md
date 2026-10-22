# Architettura

tripwatch rileva le modifiche non autorizzate sui server: nuovi utenti privilegiati, chiavi SSH,
persistenze (cron, systemd, binari SUID, file immutabili), codice applicativo modificato senza un
deploy dietro, webshell, skimmer e pattern di attacco nei log dei web server. È indipendente dallo
stack: il nucleo non sa nulla di linguaggi o framework, e tutto ciò che è specifico sta in profili
che si attivano quando la scoperta automatica trova la tecnologia corrispondente.

## Componenti

**Sensore** (`cmd/tripwatch-sensor`): un binario statico su ogni macchina monitorata. Osserva e
riferisce, non decide mai. Come servizio invia un battito al minuto e uno snapshot completo ogni
ora, dentro buste firmate. In futuro gli eventi critici (utenti, chiavi, sudoers, setuid, nuove
unit e righe di cron, moduli del kernel) partiranno appena accadono.

**Verificatore** (`cmd/tripwatch-verifier`): gira su una macchina dedicata. Tiene baseline e
manifest di build fuori dai server monitorati, confronta, applica le regole e genera gli allarmi.
Non ha credenziali per le macchine monitorate: sono i sensori a inviargli i dati.

## Trasporto

Il sensore spedisce in push al verificatore su TLS 1.3 con certificato client
(`internal/transport`). Ogni busta viene sigillata, salvata su disco con `fsync` e rinomina
atomica, e solo dopo spedita: se la conferma si perde, al riavvio parte la stessa busta, che il
verificatore riconosce e accetta una volta sola. Il pacchetto di registrazione contiene la CA, il
certificato e la chiave TLS del server e una chiave Ed25519 di firma, distinta da quella TLS.

## Verificatore

- **Ricezione** (`internal/verifier/ingest`): il nome comune del certificato client deve essere
  l'identità dichiarata nella busta; firma e catena si verificano con la chiave registrata. Le
  buste dello stesso server passano una alla volta e la posizione nella catena si aggiorna solo se
  è ancora quella verificata, quindi due buste non possono estendere lo stesso anello. Uno
  snapshot oltre il terzo in 15 minuti viene rifiutato prima di qualsiasi lavoro.
  Una catena rotta o ripartita è un allarme critico.
- **Archivio** (`internal/verifier/store`): SQLite. Gli snapshot restano tutti per 48 ore; poi,
  fino a 30 giorni, l'ultimo di ogni giorno e quelli che mostrano un cambiamento o una condizione
  nuova insieme al precedente; il primo di ogni server per sempre come baseline. Oltre 1 GB di
  snapshot in 24 ore un server viene verificato ma non conservato, con un allarme. La conservazione è per età e mai per numero, così un
  server compromesso che inonda di snapshot non può spingere fuori le prove; snapshot orari di un
  server stabile sono quasi identici, e diradarli tiene il database a pochi giorni per server.
  Ogni minuto in cui arriva un battito o uno
  snapshot viene annotato per 7 giorni: da qui l'interfaccia ricava i silenzi di ogni server.
- **Analisi** (`internal/verifier/analyze`): una coda nel database, analizzata in ordine. Ogni
  snapshot è decompresso con limiti di dimensione, numero di valori e profondità, poi confrontato
  con il precedente. Le regole producono condizioni (stato pericoloso in sé, chiuse quando
  spariscono, tranne critiche e alte) e cambiamenti. Ogni minuto un controllo solleva l'allarme
  per i server muti e per quelli che mandano battiti ma non più snapshot.
- **Allarmi**: un'impronta per condizione e server; la stessa condizione aggiorna l'allarme
  esistente invece di crearne uno nuovo e lo riapre se era risolto.
- **Notifiche** (`internal/verifier/notify`): critici e alti per email, un messaggio per giro.
- **Interfaccia** (`internal/verifier/ui`): HTML reso dal server, template e asset incorporati nel
  binario, nessuna build frontend. Il colore compare solo sulle deviazioni e ogni gravità ha anche una forma. Sessioni da 12 ore con
  token conservati solo come hash, token CSRF derivato dalla sessione, controllo dell'origine dei
  moduli, limite ai tentativi di accesso, Content Security Policy senza script né stili inline:
  i testi raccolti sui server possono essere scritti da un attaccante e vengono sempre mostrati
  come dati.

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
- gli allarmi critici e alti si chiudono solo a mano, perché un server compromesso potrebbe
  ripulire la condizione che li ha sollevati;
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
  userspace che lavora sui descrittori come il kernel: ogni componente si apre con `openat` sul
  descrittore della directory precedente con `O_NOFOLLOW`, i symlink si leggono dal loro
  descriptor e `..` torna indietro su una pila di descrittori senza superare la root. In quel
  caso lo snapshot riporta comunque un avviso (`warnings`), perché il confinamento non viene dal
  kernel. `/proc` fa eccezione: i suoi link speciali servono al collector dei
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

Prima di leggere qualunque contenuto, un passaggio elenca solo i nomi nelle cartelle di upload e
segnala gli script: costa soltanto il listing, così file lenti da leggere (sparsi, milioni di
immagini) non possono spingere una webshell oltre la scadenza. Il passaggio sui contenuti poi
arricchisce gli stessi finding con le firme, o li ritira se il file è un segnaposto vuoto. Le
cartelle di dati si leggono in streaming e non si hashano; una cartella di codice con più voci
del limite viene ispezionata allo stesso modo. Dentro le upload i symlink vengono segnalati e mai
seguiti; si segue soltanto una cartella di upload che è essa stessa un link, e solo verso
l'applicazione o la cartella che contiene le sue release.

## Log dei web server

`internal/weblog` non fa I/O: trasforma una riga in una richiesta normalizzata (formato combined e
JSON di Caddy, path decodificato due volte contro il doppio encoding) e applica le regole, con
uno stato per IP limitato per correlare le catene. Lo stesso codice servirà al verificatore sui
log grezzi.

`internal/collector/logs` legge i file con un tetto per riga (`MaxLineLength`, oltre si salta alla
riga successiva senza tenere i byte in memoria), per file e per giro, e con mappe limitate durante
la scansione. Con l'offset salva l'hash degli ultimi 4 KB letti: al giro dopo, se quei byte sono
cambiati o il file è più corto dell'offset, il log è stato riscritto o troncato nello stesso
inode, ed è un evento. Alla rotazione cerca il vecchio file fra i fratelli per inode (`.1`, `dateext`,
nomi con data di Caddy) e ne rilegge la coda dall'offset salvato; un file svuotato in place con
una copia accanto il cui contenuto coincide con l'impronta salvata è `copytruncate`, non un
troncamento. Se il file precedente non si trova, lo dice. Un tratto senza a capo più lungo del
limite per giro viene saltato con un'issue, invece di fermare l'offset. Gli eventi hanno un tetto:
oltre, un evento entra solo al posto di uno strettamente meno grave, così un flood di eventi di
una gravità non tiene fuori quelli più gravi. Gli IP sono contati con il riassunto di Misra-Gries
e le tabelle per IP delle regole sfrattano invece di rifiutare. Di una riga oltre il limite si
tengono testa e coda: la testa contiene metodo, path e status, la coda una riga vera scritta
dopo un buco di byte nulli, che i web server non scrivono mai e che vengono trattati come
separatore. Una copia usata per riconoscere `copytruncate` vale solo se il proprietario del log
non poteva scriverla. Le posizioni nuove restano in sospeso finché il chiamante non conferma la
consegna dello snapshot con `Commit`: un giro perso viene riletto.

## Applicazioni

`internal/collector/apps` è l'unico collector che apre connessioni: verso il database delle
applicazioni riconosciute, con le credenziali della loro configurazione. Le query sono solo
`SELECT`, con prefissi di tabella validati e parametri passati come argomenti; i risultati sono
limitati a poche centinaia di righe per query. Per l'host `localhost` si usa il socket Unix
dentro la root osservata, come fa il client `mysql`. I valori presi con `getenv()` si risolvono
dall'ambiente dei processi PHP e dei loro antenati. Le query passano da un'interfaccia
(`querier`), così i test non richiedono un database.

## Struttura dei package

| Package | Ruolo |
|---|---|
| `internal/protocol` | formato delle buste, firma, verifica della catena |
| `internal/discovery` | ambiente di esecuzione, runtime di container, siti di nginx, Apache e Caddy con il loro routing, applicazioni e runtime attivi |
| `internal/collector` | contratto dei collector, snapshot, descrizione dei file (hash, proprietario, flag dell'inode) |
| `internal/collector/system` | account, SSH, sudoers, cron e at, unit systemd, hook di avvio, processi, socket, verifica dei pacchetti, file privilegiati |
| `internal/collector/web` | per ogni applicazione: albero di hash del codice, upload, poliglotte, firme di webshell, file nascosti, script raggiungibili |
| `internal/weblog` | parsing dei log di accesso, regole d'attacco, redazione delle richieste |
| `internal/collector/logs` | lettura incrementale e limitata dei log, eventi, statistiche, posizioni con commit |
| `internal/collector/apps` | configurazione e database delle applicazioni: amministratori, script salvati, estensioni, impostazioni |
| `internal/transport` | sigillo, salvataggio e spedizione delle buste dal sensore |
| `internal/verifier/pki` | CA privata, certificato del server, pacchetti di registrazione |
| `internal/verifier/ingest` | ricezione su mTLS e verifica della catena |
| `internal/verifier/store` | archivio SQLite: server, snapshot, attività, allarmi, utenti, sessioni |
| `internal/verifier/analyze` | decodifica limitata degli snapshot, regole, silenzio dei sensori |
| `internal/verifier/notify` | email degli allarmi |
| `internal/verifier/ui` | interfaccia web |
| `internal/buildinfo` | versione inserita al momento della build |

`deploy/verifier` contiene Dockerfile e `docker-compose.yml` del verificatore, `deploy/systemd` la
unit del sensore. Previsti: `internal/collector/...` per i container, un DaemonSet Kubernetes.
