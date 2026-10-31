# Changelog

All notable changes to tripwatch. Each release lists what changes for the sensor and for the
verifier, so it is clear which of the two needs updating. Versions follow
[Semantic Versioning](https://semver.org/); before 1.0 a minor version may change behaviour.

## [Unreleased]

### Sensor

- Decoy files: the paths listed in `/etc/tripwatch/decoys` (`-decoys-file`), one absolute path
  a line, the file owned by the sensor's user and readable by it only, since the command line is
  readable by every local user. The `decoys` collector reports their metadata, hard links
  included, and the other paths found leading to one, and is reported with an empty list when
  there are none, or when the file is refused, with the reason in its errors. No collector or
  watcher opens a decoy, by its path or a link, attributes included. Files the sensor reads are
  opened with `O_NOATIME` where the kernel allows it.
- The web collector names the release of each drupal.org project in a Drupal site's
  modules/contrib, themes/contrib or profiles/contrib, from the project and version drupal.org's
  packaging writes into its .info.yml. Releases are named for every package installed, changed or
  not (200 an application, those with changed files first, 1,000 files read for headers), and
  WordPress's own release always.
- The web collector names WordPress's own release, with the locale of wp-includes/version.php,
  when files outside wp-content changed.
- The web collector names the release of each WordPress plugin or theme a changed file belongs
  to, its slug and version read from the plugin's header as WordPress finds it or the theme's
  style.css (200 plugins at most an
  application, the first 8 KB of a file): the verifier can compare the changed files with that
  release as published.
- A script saved in UTF-16 is decoded to UTF-8 before the skimmer search, as a browser decodes
  it: told by its byte order mark, little or big endian, or without one by the zero byte beside
  each ASCII character of its start. The file's size, already counted in the run's budget, bounds
  the work. One without a mark whose start is mostly outside ASCII, which only a charset the
  server or the page declares makes UTF-16, is read as it is: a limit of the rule.
- Strings that a browser reads as a URL are read so before the search for a way out: C0 controls
  and spaces at their ends and tabs and line breaks inside dropped, a backslash taken as a slash
  and the slashes after `https:` made two, as the URL parser of browsers does, and the host
  mapped as UTS 46 maps it (`golang.org/x/net/idna`, now a dependency of the sensor: full-width
  letters and the ideographic full stop are ASCII). `fetch(' https:\\evil\u3002example')` names
  its host. Brackets that only group a name are dropped from the source as the tokenizer renders
  it, so `new` and two thousand brackets around `Image` is `new Image`, and the escapes `\t`,
  `\n`, `\r`, `\b`, `\f`, `\v` and `\0` in strings are decoded.
- More ways out are read as one: a URL's host percent-decoded, an IPv4 address in any of the
  number forms a browser takes, an IPv6 address, a host without a dot; the text of a template
  before its first substitution; a URL held in a constant, written in place of its name; the URL
  passed through brackets, a sequence (`(0,'https://...')`), `.call`, `Reflect.apply`, a
  `Request`, the base of a `URL`; and an image's or a script's `src`, a link's or the location's
  `href`, a form's `action`, `location.assign`, `window.open` and `EventSource`; markup written
  with `document.write`, `innerHTML`, `outerHTML` or `insertAdjacentHTML` whose `src`, `href` or
  `action` names another host, quoted or not; `setAttribute('src'|'href'|'action', ...)`,
  `Object.assign` with one of those properties, `import()`, `new Audio` and `new Worker`. A
  payment field's name is read as CSS selectors match it: CSS escapes decoded (`\63 vv` is
  `cvv`), and a name's start, middle and end given by selectors on one element
  (`[name^=card][name$=number]`) put together, also when they leave out up to half of a known
  field name between them. A payment field's name inside base64 data, the payload of a data URI
  that a string holds (a quote, `data:`, a media type and `;base64,` before it) or a whole quoted literal that decodes into data that is not text, is chance and not counted;
  a run of code or of joined strings in the same letters (`(0+0+...+cardnumber.value)`) is
  never taken for it. The clean corpus flags the same files.
- The families search, around each fixed word, the whole statement or line it is in (at most
  4 KB each way), regions that touch merged into one: a call through seventy brackets or a host
  with a 63-character label is no longer longer than the window, and a file made only of those
  words costs at most about 1.2 s per MB instead of 20, since every byte is looked at once. Text is
  folded as Go's case-insensitive patterns folded it (ſ is s, the Kelvin sign is k). A file taken
  for UTF-16 without a byte order mark is read both ways, decoded and as it is, since UTF-8 with
  zero bytes in a comment imitates it. The decoders also run on the source as the tokenizer read
  it, where `globalThis['at'+'ob'](...)` is `atob(...)`.
- The tokenizer of the skimmer search is checked in the tests against a JavaScript parser,
  `github.com/tdewolff/parse/v2` (a test dependency only, in no binary), on 20,000 generated
  scripts dense in the places a "/" or a quote can be misread, and with `WEB_CORPUS` on every
  script of a corpus: on the 16,663 valid generated scripts it finds the same strings and
  patterns, and on the 1,975 valid scripts of the corpus the same number of patterns. The
  comparison found three mistakes, fixed: a "/" after "*" never started a pattern (`a */re/`), and
  a label's block and a statement after a finished expression and a line break were taken as
  uncertain.
- The skimmer search costs a fifth of what it did in 0.1.42: about 0.1 s per MB of changed
  script on generated input and 0.25 on real bundles, against 1.1. Go's case-insensitive
  patterns folded every character and tried their alternatives at every byte: the text is now put
  in lower case once, and each family runs only around the fixed words its matches hold (`cc`,
  `card`, `fetch`, `sendBeacon`, `atob`...), with the same answers, which a test checks against
  the full patterns on generated text. The clean corpus reads in 18 s, was 100.

### Verifier

- Decoys: high alerts for a decoy removed, replaced or rewritten, one listed and missing (also in
  the first snapshot), one with another hard link, a path leading to one, and each decoy of a
  sensor that stops listing it or stops reporting decoys at all. A decoy missing and then put in
  place raises nothing.
- A directory whose code changed is named in the alert of one of its files when that alert is
  high or critical, with the other files changed there, instead of a medium alert of its own: a
  backdoor in one plugin file raised three alerts, now one.
- Content references, off by default (`TRIPWATCH_CONTENT_REFERENCES=on`): the changed files of a
  WordPress plugin or theme, and those of WordPress itself outside wp-content, are compared with
  the release as published on WordPress.org, by SHA-256 at the same path. A theme's release is
  made from its archive in WordPress's directory, which no checksum list cross-checks. A
  drupal.org module, theme or profile is compared with its release too: the zip archive its
  release history names, which must come from ftp.drupal.org with the size and MD5 the history
  gives. Drupal's core is not compared: installed with Composer, its files sit where no archive
  puts them. A core release is made from
  the official archive for its version and locale, hashed by the verifier within bounds (64 MB,
  256 MB expanded, 50,000 files) and kept only when every file matches the MD5 list
  api.wordpress.org publishes. An update as published raises nothing, not even the change of its
  directory; a file the release lacks or has with other content is a high alert naming the
  release. Published is not harmless: a plugin, theme or project the host never had is a medium
  "installed" alert even when it matches its release (a slug can be squatted, a release can be
  malicious), and one whose version went down from the last the verifier saw for that host, in
  any snapshot, is a medium "downgraded" one; the verifier remembers each host's releases (5,000
  packages a host at most), whatever snapshot named them, and the first snapshot only records. Checksums are fetched from one
  fixed host, slugs and versions checked against strict shapes, at most five fetches an analysis
  round and fifty a server a day, kept in the database up to 2 GB. A release the source lacks or
  could not give (an error, a timeout, a list too large or malformed) is remembered for a day,
  fetches run apart from the analysis, which never waits for them, so a release is judged from
  the snapshot after it is fetched, and a redirect may change neither host nor scheme. Signatures
  and the skimmer search still read every changed file.

## [0.1.42] - 2026-10-30

What changes for an operator, in short; the details follow by component.

- **New alerts.** A payment skimmer is searched for in every changed script, across statements
  and pieces of a file that try to hide the strings it builds; scripts left unread run after run
  raise a medium alert each, and an application behind on its skimmer search a high one. What a
  collector could not check raises one low "Analysis incomplete" alert per collector. A
  container whose bind mounts its kernel does not show, a cron line that never runs on
  schedule or fetches and runs code, and the loader's cache naming a library directory the
  system does not own raise alerts of their own.
- **Host page.** A "What the sensor could not check" panel lists each collector's issues, work
  left undone apart from notes such as a network filesystem skipped by design.
- **Less noise.** Scripts changed together, as a deploy changes them, are one alert instead of
  one per script and directory; a package manager lowers only root's files and never hides a
  file under a staging name in `/tmp` or `/dev/shm`; issues that are notes raise nothing. On the
  fleet today no host gets the new "Analysis incomplete" alert.
- **Declared limits.** Until the sensors are updated, their search for hidden processes stops at
  the same PID every run and shows only on the host page. A "/" after the body of an arrow
  function, or after a bracket opened before the piece read, is still read both ways.
- **Upgrade.** Update the verifier, then the sensors: the new alerts need both.

### Sensor

- A start-up hook that is a symlink takes the later of its own change time and its target's,
  and says where it leads: a link made in `/etc/profile.d` to a file written before the previous
  snapshot is now a new hook, not one that was there all along.
- A script in an upload path answered with a permanent redirect stays high unless the script is
  the path's last segment with nothing after it: `x.php/a.php`, `x.php/` and `x.php/y.php.jpg`
  run `x.php` through PATH_INFO, which chooses its own status.
- Changed scripts a run left unread for skimmers, for its time, its budget or past the 2,000 it
  reads, keep their old entry in the code manifest it hands on, marked pending: the next run finds
  them changed again and reads them first, then the smallest, so decoys go last; one script cannot
  take more than 20 seconds of the run. Past the 2,000 a pending script takes the place of a new
  one, and a run whose hash budget ran out does not clear it. A script left unread three runs in a
  row is named in the result (the hundred unread longest, the rest counted), and the verifier
  raises a medium alert for it that the sensor cannot close by no longer naming it. Applications
  whose scan was cut short go first at the next run. Per application the collector counts the runs in a
  row that left changed scripts unread for any reason (a search cut by the run's time counts as a
  cut scan too), not starting over while a pending script disappears; a scan cut before its search
  neither adds nor starts over. From the third, the verifier raises a high alert naming the
  application and the scripts unread longest. Rebuilt from a week of a fleet of 99 applications,
  it would have raised for none: their only unread runs were scans cut on two hosts, which the cut
  scan alert names. The count starts over only after three runs in a row read every change, so a
  script taken away for one run does not reset it. Past the 2,000, candidates are kept by how
  long they have been pending, and among those pending as long by a random draw, so the order of
  the walk cannot keep the same scripts out run after run.
- The web collector counts the runs in a row each application's scan was cut short by its time
  limit, and the verifier raises one medium alert for the host when an application reaches three:
  in a week of a fleet of a hundred applications, cuts came alone or in pairs but on two hosts.
- The kernel's socket tables are read as streams: a table grown past 16 MB by anyone's
  listeners was dropped whole, root's listeners with it; now every row goes through the bound
  that keeps root's sockets and the listeners first, up to a million rows a table.
- A path with `..` read inside the observed root no longer fails while renames happen elsewhere
  on the system: the kernel refuses it then with EAGAIN, which any user could keep causing with a
  rename loop to stop the sensor following an application's shared upload link. It is tried
  again, then resolved the userspace way, confined the same.
- A batch of real-time events stays under the verifier's limit once in its envelope (it could
  pass it by a few bytes when full, as the web user can make it with long names in the uploads),
  and a batch refused for its size is no longer taken for delivered: its events go again in
  smaller batches, root's first, and the counts of lost events it carried are kept.
- A heredoc label longer than 128 bytes, or after more than 16 blanks, is a signature in a data
  file (`long_heredoc_label`): with a body of `/*` or `?>` it hid the payload after it, with a
  full `<?php` tag and the default configuration.
- In a block opened by `<?` and a blank, as dumps and logs quote it, a backtick around a bare
  word counts when the block also calls something it does not name: through a variable
  (`$f("PATH=...")`, `$a[0](`, `${"f"}(`), an expression or a string (`("put"."env")(`,
  `"putenv"(`), a callback (`array_map`, `call_user_func`...) or a method that calls what it is given
  (`ReflectionFunction::invoke`, `Closure::fromCallable(...)->__invoke`), a filter's
  `FILTER_CALLBACK`, an anonymous class passed to `array_find` and the other PHP 8.4 callbacks, any of which can be putenv, so
  that the word runs from the attacker's directory.
- `<?echo`, `<?print`, `<?const` and constants followed by an operator (`<?PHP_EOL>1;`) open
  code, not a processing instruction: only a lower-case target, an undefined constant on which
  PHP 8 stops, is left to the named signatures, and only until a block PHP runs appears in the
  file, since that block can define the name (`<?php define("foo",1);?>` then `<?foo>1;`, also
  with `xml` and `php`, followed by a blank or not; only a real `<?xml version=` prolog stays
  text). A definition in another file the same request includes is past what a search of one
  file can see.
- With short open tags, `<?` glued to code other than an XML processing instruction opens a
  block searched with the weak signals: `<?$c=$_GET["c"];system($c);`, `<?@`, `<?(function`,
  `<?/**/`, `<?echo"`, `<?PHP_EOL.$c=` and `<?E_ALL|` in a data file are now found. Only a
  target followed by `?>`, `>` or a pseudo-attribute (`<?mso-application progid=`) counts named
  signatures alone. `<?>` opens nothing, and syntax PHP never compiles (`=> {`, `[^`) keeps the
  minified scripts a cache holds from being taken for code.
- A volume of the local driver binding a host directory (told by its mount options, so `/dev/shm`
  bound counts) is checked against the container's mount table like a bind, and its mount point on the host (the volume's `_data`) is the volume itself,
  not a directory of the runtime's state.
- A running container whose mount table lacks a host directory or file its configuration binds
  (the source swapped after the start, or the process chrooted away from it) has its mounts "not
  verified by the kernel", a power of its own.
- A package whose scripts change by the dozen is left out of the skimmer search only when its
  version file changed in the same run (`style.css`, `readme.txt`, the main plugin file,
  `composer.json`, `package.json`, `etc/module.xml`, `.info.yml`): decoys written next to a
  skimmer in a theme no longer hide it. Payment field names split across `atob` literals,
  reversed with `split("").reverse()` or built with `String.fromCharCode` are decoded, and the
  expressions a script builds from string literals only are folded by a bounded tokenizer:
  escapes, comments between the pieces, parentheses, `+`, `.concat()`, `[..].join()`, `atob()`,
  template literals with literal substitutions, and constants assigned earlier in the file. It also
  folds `.slice()` and `.replace()` with literal arguments, starts at brackets before a literal,
  skips regular expression literals (never after `++`/`--` or a keyword used as a property's name;
  after a `)` or a `}`, which a tokenizer cannot tell a division from, the script is folded both
  ways and the strings of both kept), keeps constants from one piece of a large script to the next and,
  past its bound, keeps a name the piece uses again over decoys it never uses. A script that uses
  more than 2,048 string constants, or nests brackets past 64 levels, is named in the issues. The folding stops concatenating at its bound, starts only where a string can, reads at most a few
  million terms a piece, and the skimmer search stops with the run's time, naming what it left. A literal left open passes over its
  whole window, what is folded never outgrows the piece four times over, and constants past
  the bound go half at a time.
- A web log event takes the method of a request that sends something over the reads before it.
- The `hooks` collector reads dpkg's file lists as streams and names the hooks a package owns.
- The `hooks` collector reports where the loader's cache puts `libc.so.6`, with each entry's
  architecture, reading the whole cache for it even past the bound on directories.
  It also reports the flags of its own architecture's libc, and a cache too large to read,
  which the loader still uses, as truncated instead of leaving it out.
- The powers in a container's real-time event are clipped like its other fields: binds of long
  paths can no longer make the event too large for the verifier and lose it.
- The container watcher keys a container also by its image digest and forgets a key an hour
  after its last container is gone: an image swapped under the same name, tag and powers is
  reported with the digest it replaces (the digest last seen for a key is kept as long as the
  sensor runs), and the same container started again hours later is reported again instead of
  never until the sensor restarts. CRI-O containers carry their image's ID.
- The search for hidden processes goes on from where the previous run stopped: with `pid_max`
  in the millions its ten seconds a run reached about half the PIDs, the same half every time, on
  eight hosts of the fleet. Every PID is now probed within two or three hourly runs, and only a
  sweep that takes more than three runs is reported as an issue.
- A "/" after ")" or "}" divides or starts a pattern depending on what the bracket closed, and
  the skimmer search now knows it as JavaScript tokenizers do, from a stack of what each open
  bracket started: the condition of an `if` or a loop, an expression, a block, an object, a
  declared function or class, a function or class expression. Scripts that asked for one reading
  in one place and the other elsewhere no longer hide the strings they build. The stack decides
  only in a closed list of cases a tokenizer is sure of: anywhere else (a conditional's or a
  label's "{", a line break after `return`, `of`, `await` or `yield`, which can be names) the
  "/" is still read both ways, the whole script and each statement again. A function
  expression's body holds statements, so a label inside one is a label. The stack goes on from
  one 1 MB piece to the next, with the template, string, pattern or comment left open where the
  next piece starts. A template literal with a real substitution is read as JavaScript reads it,
  its text passed over and each substitution read as code: its closing backtick no longer opens a
  template that hid the next 4 KB. Strings, templates and patterns longer than the 4 KB the
  folding keeps are passed over to their real end, never read as code from the middle; the
  comments a browser reads in a script (`<!--`, `-->` first on its line, a first line `#!`,
  after a byte order mark too) are comments, and read as operators too, as a module reads them.
  A pass before the tokenizer maps every white space of JavaScript (Unicode's space separators,
  the no-break space, the byte order mark, vertical tab, form feed) to a space and every line
  terminator to one, U+2028 and U+2029 staying text inside a string, where a backslash before
  them continues the line. Whether a piece starts a line goes on from the piece before. The
  clean corpus reads faster (74 s, was 83).
- The skimmer families are also searched on the script as the tokenizer read it: comments
  dropped, white space and escapes in names undone (`new/**/Image(`, `Imag\u0065`,
  `navigator. sendBeacon(`), literals joined by `+` read as one string, so a host split across
  them is named, and a member named by a string read as the member (`navigator["sendBeacon"]`).
  A constructor matches through brackets and a global object (`new(Image)()`), a file is cut in
  pieces on character starts, and a script that may be a module is read every way as one too.
  The search costs about twice as much (1.1 s per MB of changed script).
- An application's findings are bounded by the alert they raise: those that raise none (a link
  out of the application, an `.htaccess` with no handler, an encoded blob) have a bound of 200
  of their own, and past the bound of 1,000 a finding takes the place of a less severe one. A
  thousand harmless `.htaccess` files in the uploads filled the bound before the skimmer search,
  which then dropped the skimmer it found without a word. A skimmer the bound leaves out keeps
  its script pending, and the findings left out are an issue.
- `header_register_callback` and `mb_ereg_replace_callback` count among the callbacks that can
  call `putenv` before a backtick in a data file.
- Directories renamed in a loop by any user no longer put off the sensor's next plan of its
  watches: a watched root moved away and back is watched again within a couple of seconds, while
  the loop runs, instead of staying blind until it stops.

### Verifier

- What a collector could not do reaches the operator: the issues each collector reports (a bound
  reached, a file not read, a search given up, a script named past what a rule follows) raise one
  low alert per host and collector, naming twenty and counting the rest, closed when the collector
  no longer reports them. Until now only the container issues raised one, and every limit
  "named in the issues" stayed where only the sensor saw it. Notes do not raise it: a network
  filesystem skipped by design, why a PHP file of the uploads counts as code, and the hidden
  process search of older sensors, which stopped at the same PID every run. On the fleet today
  every issue is one of these, so no host gets the alert. The host page lists every collector's
  issues in a panel, work left undone apart from the notes. The twenty issues kept of a collector are the most
  serious: the skimmer search left unfinished first, then other work left undone, notes last, so
  a flood of minor issues cannot push it out.
- Scripts changed together in an application are one high alert naming each with its hash, the
  other files changed and the directories whose code changed, instead of a high alert for each
  script and a medium one for each directory: a deploy that rewrites four core files raised six
  alerts, now one. A script changed alone is still an alert of its own, and the same scripts
  changed again to other contents are a new alert.
- The names dpkg, rpm and apk stage a file under are skipped while a package manager runs only
  outside the scratch directories and for no other user's file, and a package manager lowers
  only root's files in the scratch directories: the web server's user, who can read when apt
  holds its lock, could drop, run and remove a program in `/dev/shm` named `.dpkg-new` unseen.
- A package manager running no longer lowers another user's crontab, start-up file or service
  unit, in a home or owned by that user: only root's.
- A change to root's start-up files in its home (`/root/.bashrc` and the like) is high in real
  time as in a snapshot: the snapshot's own finding is dropped once an event reported the
  content, so the event's medium was the only alert left.
- A new cron line is critical, with the reason, when it never runs on schedule (the 31st of
  February, as CronRAT hides its code), downloads and runs what it fetched, decodes a base64
  payload or starts a process under another name; other new lines stay high.
- The system's own library directories are `/lib`, `/usr/lib` and the one holding each
  architecture's libc (with its `/usr` twin), no longer any directory of that shape: `ldconfig
  /usr/lib64` on a multiarch system, or a made-up `/usr/lib/<triplet>`, is a high alert. A
  loader cache or configuration past the bounds read is a high alert of its own, and more than 16
  unconfigured directories fold into one. A libc of another architecture than the sensor's makes no
  directory the system's, and the legacy hwcaps subdirectories (`tls`, `haswell`...) count as
  directories of their own: glibc no longer searches them by itself.
- A mount in a container's table at a point its configuration does not list is judged as a
  declared one: a link in the image moving a bind of `/root` or `/etc/cron.d` elsewhere is a
  power. Only the runtime's own image layers, volumes and the container's own state directory
  are left out, and not when the entry is a directory the configuration binds (a volume of the
  local driver bound to a path included): another container's layer bound through an alias of
  the data root counts under every path it shows.
- A container's mount that shows, on the host, a sensitive tree mounted elsewhere is a power:
  `-v /data:/h` where the host binds `/data/docker` at `/var/lib/docker` gives the runtime's
  state, and is judged as such.
- A request that posted to a script missing at collection time is no longer dropped as a probe:
  a web shell sent its command in the body and deleted before the run raises its alert. Failed
  reads of a missing script stay probes; in a week of the fleet's logs every one was a GET.
- Each real-time event carries whether a package manager of root held its lock when it was
  queued, read at most once a second: an installation is over before its batch leaves, so a hook
  it wrote was judged as if no package manager ran. The names dpkg, rpm and apk stage files under
  (`.dpkg-new`, `.rpmnew`...) raise nothing while one runs. In the benchmark, installing a package
  with a login hook went from three high alerts to one medium.
- A package update no longer lowers every new start-up script to low: where dpkg's file lists
  were read, only a new hook a package owns is; one no package names stays high or medium. A
  hook there before keeps being lowered, as maintainer scripts regenerate some. rpm and apk keep
  their lists in binary databases, and there an update still lowers every hook.
- A container start seen in real time on another image than the one of the same name, tag and
  powers before it raises the snapshot rule's medium "runs another image". The alert of a
  container with power over the host names the image digest in its detail, so accepting it never
  covers another image under the same tag, or says the runtime reports none, and keeps the ID and
  creation time in the title, so an acceptance holds for the same container started again;
  acceptances given before are asked once more the next time that container starts.

## [0.1.41] - 2026-10-29

Back up the verifier (`tripwatch-verifier backup`), update it, then the sensors. Its first start
seals the notification channels' settings: going back to 0.1.40 or earlier means restoring that
backup.

### Sensor

- A container health check whose shell was seen started by the runtime is no longer reported
  when the command it runs is inspected after runc has gone: the sensor remembers such shells
  by PID and start time, so a process that later takes the same PID is not trusted.

### Verifier

- The alert list exports as CSV or JSON with the filters and order it shows, every page of
  it up to 10,000 alerts, from links beside the count. CSV cells that a spreadsheet would run as
  a formula start with an apostrophe, and each export is recorded in the audit log.
- How long the verifier keeps snapshots, real-time events and resolved alerts is set in days
  with `TRIPWATCH_KEEP_SNAPSHOTS_DAYS`, `TRIPWATCH_KEEP_EVENTS_DAYS`,
  `TRIPWATCH_KEEP_RESOLVED_DAYS` and `TRIPWATCH_KEEP_RESOLVED_MINOR_DAYS`; the defaults are
  unchanged (30, 7, 90 and 7), and the console states the retention of events as configured.
- `GET /metrics`, for an API token, in Prometheus' text format: servers by state, alerts not
  resolved by status and severity, the analysis queue and its oldest wait, the database's size,
  the sensors' requests by kind and answer, and the notifications sent and failed by kind of
  channel.
- Notification channels' settings, passwords, bot tokens and webhook secrets among them, are
  sealed in the database with AES-256-GCM, those stored before at the first start. The key is
  `TRIPWATCH_SECRETS_KEY` or, without it, `pki/secrets.key` in the data volume, copied by
  `backup`. A verifier older than this one cannot read sealed channels: going back to one
  means restoring the backup taken before the upgrade.
- The overview's open alerts start with a lane of those raised in the last 24 hours, counted in
  full, set apart from those open for longer: what is new is the first question of a morning
  look.
- `j` and `k` move down and up the rows of the alert lists; Enter opens the alert or the group.
- The server list groups by a label key (Group by), one section per value with how many of its
  servers have alerts, the servers without the label last.

## [0.1.40] - 2026-10-29

Update the verifier, then the sensors: the verifier reads the new sensor's database object
hashes, integration grants and budget losses, and records the sensors' update to this version
in the audit log; older sensors keep working with it.

### Sensor

- A set-user-ID program from the system's directories that exits at once (a `sudo` whose
  command fails) is no longer reported as root gained through an unknown program: the sensor
  remembers what each process it inspected started from, and uses it when the process is gone
  by its change of user. A process whose start was not inspected is still reported.
- A script in an upload path counts only when it sits in or below the upload directory: a
  front controller that routes the rest of the path, such as `/index.php/en/images/a.jpg`,
  is no longer reported.
- Any user could make the verifier refuse the whole `sockets` or `processes` result by opening
  tens of thousands of sockets or processes, which silenced the rules on new listening ports,
  raw sockets and suspicious processes. The sensor now reports at most 20,000 sockets and
  10,000 processes, with 4 MB of command lines in all. Over those bounds what the rules read
  comes first, root's next, and what is left out is counted by owner in the result's issues.
- In the temporary directories each account spends its own share of the events of a second
  before the common budget, and a program within its owner's share spends none of it: junk one
  account writes by the thousand no longer hides another account's dropper. Events let go over
  these budgets are counted apart and raise their own medium alert, "Real-time events over
  budget in temporary or upload directories", instead of the high "Real-time events lost",
  which now counts only what a sensor that fell behind lost.
- A database dump is told by its statements only under a name a dump can have: a `.sql`,
  `.dump` or `.bak` file, or one named by date with no other extension. A `.txt` or `.ico`
  in the uploads that starts with a `LOCK TABLES` line is searched for code in full.

### Verifier

- Text from the monitored host reaches alerts and emails with its line breaks, control
  characters and invisible formatting characters shown as escapes, as titles already did: a
  file name holding a line break can no longer add a line to an alert email that reads as the
  verifier's own, and a right-to-left override can no longer show `x.php` as `xphp.png`. The
  same goes for the real-time events listed on the host page, including the ones stored before.
- A Magento admin token or integration taken over in place is an alert: a token moved to
  another administrator or rewritten, an integration whose consumer or role's rules changed,
  and a trigger, routine or event redefined by another account. The first snapshot of the new
  sensor only records the new hashes and grants.
- A kind of database objects that one snapshot could not read (a query that failed or timed
  out, as a table locked while a row is added to it can make it) is compared with the last
  snapshot that read it, so what was added in between is still reported.
- A sensor updated to the version the console ordered is recorded in the audit log as
  "sensor updated as ordered" instead of raising a low "Sensor updated" alert on every server.
  An update to any other version still raises it.

## [0.1.39] - 2026-10-29

Update the verifier, then the sensors: the verifier has no changes of its own, but sensors are
updated to its version.

### Sensor

- In a document, a PHP block is read for at most 64 KiB: a `<?=` its compressed streams hold by
  chance, never closed, opened a block that ran to the end of the file and spent a megabyte of
  the run's budget for code in data files per PDF. Code planted in a document is short and is
  still read whole.
- A database dump whose tool writes a header of its own is told by its content: a statement on
  a backticked table (`INSERT INTO`, `CREATE TABLE`, `DROP TABLE`, `LOCK TABLES`) in its first
  4 KiB, before any open tag. Its backticks are then no longer "code inside a data file".

## [0.1.38] - 2026-10-29

Update the verifier, then the sensors.

### Sensor

- On a machine up for more than about three years, the start of the web server was computed
  years before the boot (the conversion of its start, in ticks, overflowed), so every
  configuration file was reported as changed after the server started. 0.1.37's check of the
  boot against the kernel's build date, written for a wrong explanation of the same reports, is
  removed.
- WP Migrate manifests written as serialized PHP arrays, as the plugin did before it moved to
  JSON in 2024, are recognised like the JSON ones instead of reported as hidden files.

### Verifier

- `tripwatch-verifier backup` copies the database (VACUUM INTO, consistent and compacted) and
  the certificate authority to a new directory under `/data/backups` while the verifier runs:
  an upgrade no longer needs a stop to keep a way back.
- `GET /api/v1/alerts` answers with `total`, the count of every alert the filters match, and
  takes a cursor: with `after=<id>` alerts come in the order they were raised from the one
  after that ID, and `next` gives the cursor of the following page while pages are full. A
  program reads every alert once instead of guessing from the newest 500.

## [0.1.37] - 2026-10-29

Update the verifier, then the sensors: the verifier has no changes of its own, but sensors are
updated to its version.

### Sensor

- A web server configuration file touched in the second the server started is no longer taken
  for one changed after: the boot time the kernel gives is in whole seconds, so the start
  computed from it can be early by up to one. Two seconds of slack absorb it.
- Documents and archives (PDF, ZIP, Office, database dumps...) are searched for code with full
  open tags only (`<?php`, `<?=`): the short blocks their compressed streams open by chance
  spent the run's budget for code in data files, a megabyte per PDF, so hosts with many
  uploaded documents reported a gap at every run. Only signatures count in documents, and code
  planted to run there opens with a full tag.
- Where the kernel reports a boot before its own build date, as virtual machines that count
  more uptime than passed do, process start times are wrong: configuration changes after the
  web server started are then not judged, and an issue says why, instead of every
  configuration file being reported.

## [0.1.36] - 2026-10-29

Update the verifier, then the sensors.

### Sensor

- A container health check or `docker exec` is recognised also when runc is caught exiting as
  the command starts, its executable no longer readable: it counts when it runs as root and
  its own parent is a verified runtime (the shim). These were reported as the web server's user
  running a shell or curl, every few seconds on hosts whose containers have health checks.
- A database dump without its header comment (mysqldump `--skip-comments`, hosting panels'
  backups), starting with mysqldump's version comment, a `SET`, or a first `DROP TABLE`,
  `CREATE TABLE`, `LOCK TABLES` or `INSERT INTO`, is read like one with it: the backticks
  around names and code quoted in posts are no longer "code inside a data file". A signature
  that names planted code still is.
- Web requests passing PHP-CGI options in the query string (`-d allow_url_include=1 -d
  auto_prepend_file=php://input`, with a soft hyphen for CVE-2024-4577) are reported as such,
  high, instead of as path traversal.
- ClamAV run by an upload plugin with its errors sent to a file named `1` (`2> 1`, as some
  plugins write it) is recognised like the `2>&1` form; any other target still alerts.
- For a web server configuration file changed after the server read it, the sensor also sends
  when the file's inode changed and when the configuration was read.
- A command fed a here-document carries the sum of the raw text before the `<<` only, so the
  verifier can key its alert on what the command does rather than on the script it is fed.

### Verifier

- An alert for the web server's user starting a command fed a here-document is keyed on the
  command before the `<<`: deploy and server management tools that pipe a new script, with a
  random delimiter, to `ssh host sh -s` at every run raise one alert, which can be accepted,
  instead of a new critical alert each time. The script stays in the alert's detail.
- "Web server configuration changed after it started" says when the file changed, when it was
  last modified and when the server read its configuration, and points out when only the
  inode changed (owner, mode, links), so an edit not reloaded is told from a change of owner.

## [0.1.35] - 2026-10-29

Update the verifier only: the sensor has no changes, sensors on 0.1.34 stay as they are. The
verifier adds the columns and tables it needs to the database on its first start.

### Verifier

- A new console look in the colours of the new logo (a fingerprint with one broken ridge): teal
  for what can be used or is selected, coral and amber only for the severities, rounded panels.
  Dark only: the light and system themes are gone. Servers are no longer told apart by a colour,
  which competed with the severities.
- The menu groups operations and configuration, with icons, and a search box at the top of every
  page looks across servers, alerts and real-time events at once (`/search`).
- A server's page shows its alerts right after its heading, open and acknowledged ones only
  (the resolved ones one click away), then its web applications as a table: the site first,
  then what runs it and its directory, those with open alerts on top with their count, and a
  filter above when there are more than eight.
- Users and roles: viewers read the console, operators also handle alerts, administrators also
  enroll and revoke servers, order sensor updates, set up notifications and manage users (users
  made before keep administrator). Administrators invite people with a one-time link valid three
  days, in which they choose their password (12 characters at least), change roles and remove
  accounts; the last administrator can be neither demoted nor removed. The menu shows each role
  what it may use.
- Servers can be renamed: administrators give a server a name, labels (`env=prod`,
  `client=acme`) and a note from its page. The name shows wherever the server appears, its
  identity (the name in its certificate) stays and shows beside it, and the searches find names,
  labels and notes.
- An API for programs (Settings, API tokens): administrators make tokens, valid 30, 90 or 365
  days, shown once and kept as a hash, that read as their owner (`GET /api/v1/alerts` with
  `status`, `severity`, `host`, `limit`; `GET /api/v1/alerts/{id}`; `GET /api/v1/hosts`) and,
  when allowed, acknowledge and resolve alerts (`POST /api/v1/alerts/{id}/ack|resolve`),
  recorded in the audit log as `api:<name>`. A token sees the servers its owner sees, stops when
  revoked or when its owner is removed, and a browser session never counts as one.
- Enrolling a server offers another Linux with systemd too: the command installs the static
  binary of the release, checked against its `SHA256SUMS`, and the service unit of the same
  release. A development build of the verifier says why it can only enroll.
- Who sees what: a viewer or an operator can be limited to the servers carrying one label
  (Settings, Users). They then see nothing of the others: lists, counts, charts, searches and
  the tab icon leave them out, their pages answer not found, and their alerts cannot be changed,
  even by a form made by hand. The limit is applied by the store to every query of the request.
- A second factor for signing in: each user sets up an authenticator app from their account page
  (QR code or key, RFC 6238 codes of six digits), confirmed with a first code, with ten
  single-use recovery codes shown once. After the password, or a one-time sign-in link, the
  session opens nothing until a code is given; a code works once, and five wrong ones end the
  session and refuse the account's codes for 15 minutes, each wrong one after that locking
  them again. The count belongs to the account: parallel requests and new sign-ins with the
  password do not reset it, only a right code does, and every wrong code is in the audit log. A
  browser becomes a known one (with its own sign-in lane) only after its code. Replacing the
  second factor takes turning it off with a current code first; turning it on, or an
  administrator resetting it, signs the account out of its other sessions. Administrators can reset the second factor of someone who lost their phone, and
  `tripwatch-verifier user -email ... -reset-2fa` does it from the server when none can.
- The account page lists where the account is signed in (browser, sign-in, last use) and signs
  out any of them; only a session that existed is recorded in the audit log. A user keeps at
  most 50 sessions, the oldest closed first, and expired sessions, known browsers, sign-in links
  and invitations are deleted every minute instead of staying in the database.
- Searches (the top search box and the alert list's text filter) run on read-only connections
  of their own, at most five seconds each, and the real-time events they look through are the
  newest 50,000: text a server chose can no longer make a search hold up what the servers send.
- The health check (`/healthz`, used by the container's `healthcheck`) now asks the database,
  so a verifier whose database stopped answering shows as unhealthy instead of ok.
- A webhook that answers with an error is reported by its status only: its answer, which may
  come from inside the verifier's network, is no longer shown. Telegram's answers still are.
- An audit log (Settings, Audit log) records who signed in, handled alerts, enrolled, revoked,
  ordered updates, changed notifications and managed users, only ever added to, the oldest
  dropped past 100,000 entries.
- Notification channels set up from the console (Configuration, Notifications): email (SMTP, TLS
  required), Telegram chats and webhooks (JSON with a `text` field chat tools show and the
  alerts, signed with HMAC-SHA256 in `X-Tripwatch-Signature`). Each receives the alerts at or
  above its severity (critical, high or medium) raised after it was added, has a test button and
  shows its latest send or error; one that fails raises an alert of its own, and alerts are
  marked sent once any channel took them, so the others are not repeated. The email set in the
  environment keeps working as before, listed read-only. The menu warning now says when alerts
  go nowhere and links to the page.
- An alert's page shows what else happened on its server an hour either side: the other alerts
  and the real-time events, so the question that comes next is answered on the same page.
- Low severity marks in charts are lighter, readable against the panels, and a web application
  with open alerts is raised on a lighter row instead of a red one whatever the severity.
- With more than 30 servers the overview draws only those needing attention (silent or with
  open alerts), at most 30, and counts the rest, healthy and not, with a link to the servers
  page: two hundred green cells no longer bury the one that is not.
- The alert list says how many alerts match in all ("201-700 of 18,342"), not how many it
  loaded, counts the hidden low notes exactly, and pages through the rest 500 at a time.
- Alert lists show when each alert was first seen and its latest activity, and tag "new" the
  ones that first appeared in the last day, so new deviations stand out from recurring ones.
- Alert filters apply as soon as a choice is made, and `/` moves to the search box. Who handled an
  alert is shown only while it is acknowledged or resolved, not on an alert open again.

## [0.1.34] - 2026-10-29

Update the verifier, then the sensors.

### Sensor

- A process's command line and `LD_PRELOAD` are reported up to 4 KB (the sensor still judges the
  whole command): any user could start processes with megabytes of arguments and make the
  snapshot too large for the verifier.
- A snapshot's results are bounded to 30 MB together, the largest left out first and named in
  the snapshot's errors, so the snapshot always fits what the verifier accepts.
- An envelope the verifier refuses for its size (413) is dropped and the chain taken back to
  before it, instead of staying pending and holding back every heartbeat, event and snapshot
  after it, even across restarts.
- In data files, a block opened by a name glued to `<?` that PHP goes on from (`<?PHP_EOL;`,
  a call, a label) counts like any block, weak signals included; only names PHP stops on, such
  as XML processing instructions, count for named signatures alone. A backtick around a bare word
  is ignored only in blocks opened by `<?` alone or by such a name, as SQL dumps quote names;
  in a `<?php` block any backtick runs a command. `putenv`, `mail`, `mb_send_mail` and
  `error_log` count as dangerous calls.
- Laravel's scheduler quoting its binary and script (`'/usr/bin/php8.3' 'artisan' ...`) is
  recognised again: judging the command as it runs made the quotes visible.

### Verifier

- Systemd scopes and their drop-ins (one per container a runtime starts, with its resource
  limits) are not reported as new services: a scope runs nothing itself.
- Docker's resolver for user-defined networks (dockerd on `127.0.0.11`, a new port at every
  container start) is not a new listening port; anything else listening there still is.

## [0.1.33] - 2026-10-29

Update the verifier, then the sensors.

### Sensor

- Apache's configuration is judged stale against its oldest worker, as nginx's: the graceful
  reload log rotation runs every night rereads it in a master started long before, and every
  file changed since that start was reported as not loaded.
- A container's health checks and `docker exec`, started by the container runtime (runc, crun,
  containerd's shim, conmon), are not taken for a web shell when they run as the web server's
  user.
- Framework commands run through BusyBox's shell (Alpine), with `exec` in front (queue
  supervisors) or in Laravel's background form are recognised as the scheduler's work; a
  framework command with anything a shell interprets besides the redirection to `/dev/null`
  no longer is.
- ClamAV run through the shell on one uploaded file, with options only, as upload plugins do,
  is not taken for a web shell; anything more in the command still is.
- The shell an error reporter starts from the PHP pool to read the project's git root (Flare and
  Ignition in Laravel, `echo $(git rev-parse --show-toplevel)`, matched whole) is not a web shell.
- Process starts are judged on their command line as the kernel gives it, not on the redacted
  one: the redaction dropped the `;`, `|` and `&` of a shell script, so a scheduler's command
  followed by anything (`artisan x; curl ...|sh`) passed for a plain one. The redacted command
  line keeps those separators as written (`2>&1` was shown as `2> 1`).
- Symfony's Console asking for the terminal size (`stty`, `stty -a`, through the shell silenced or
  filtered for the columns, BusyBox's applet included) is not a web shell; ClamAV scanning an
  upload may send its errors to its output (`2>&1`).
- The directories the loader's cache (`/etc/ld.so.cache`, glibc's format, bounded) searches and
  those its configuration names are reported with the hooks.
- The hooks of a home are described up to 64 files per pattern (the system's up to 1,024), the
  rest counted in the issues: an account filling its `.config/autostart` made every snapshot of
  the server too large to be accepted. Hook files carry their inode change time.
- The hidden manifests WordPress migration plugins (WP Migrate's media sync) leave in the uploads,
  a UUID name holding JSON, are not hidden files; their content is still searched for code.
- More persistence places are collected and watched in real time: the SSH login scripts
  (`/etc/ssh/sshrc`, `~/.ssh/rc`), the scripts root runs when a network interface changes state
  (ifupdown's `/etc/network`, NetworkManager's `dispatcher.d`, networkd-dispatcher, dhclient's
  hooks; ppp's in snapshots only), `/etc/bash_completion.d` and the loader's search path
  (`ld.so.conf`, `ld.so.conf.d`).
- The search for PHP in data files no longer opens a block on `<?` and a blank when short open
  tags are off, as PHP does not: a comment opened there could hide a real `<?php` block written
  after it. With short tags on, a word starting with `php` or `xml` glued to `<?` opens a block
  when a goto label, a class constant or a call follows (`<?phpinfo:`, `<?php_x::class;`),
  blanks and comments in between included. Any longer name glued to `<?` (a constant such as
  `PHP_EOL`, a namespaced class) opens one too.
- A backtick around a bare word in a data file is not taken for a command: SQL dumps quote every
  table and column that way, and a `<?` left open in one made a critical alert of a backup. A
  backtick passing input or arguments (`$c`, `ls -la`) still is.

### Verifier

- A loader configuration file written and removed within minutes is a critical alert: the
  directories it named stay in `ld.so.cache` after it is gone. A change to the loader's search
  path is its own high alert; `~/.ssh/rc` changes are judged as the account's start-up files.
- Start-up, login, network and loader hooks added or changed between two snapshots are an
  alert (high in the system, medium in a home, low when packages changed in the same interval),
  unless a real-time event already reported that content: changes made while the watcher was
  stopped or past its bounds were only listed. Files collected for the first time and changed
  (by their inode change time, which `touch` cannot set back) before the previous snapshot are
  not reported as new, so updating the sensor raises nothing. Only a change of package versions
  lowers them, not `apt-mark hold`; files without a hash are compared by type and size.
- A directory in the loader's cache that neither its configuration nor the system's library
  directories name is a high alert: `ldconfig /dir` puts one there without any configuration
  file, and a library in it with a system library's name is loaded instead.
- A collector result with more than 500,000 values, or past 1,000,000 together with the others
  (smallest first), is refused alone and reported as that collector's error: one inflated result
  no longer makes the whole snapshot refused.

## [0.1.32] - 2026-10-29

Update the verifier, then the sensors.

### Sensor

- A snapshot cut short by the sensor's own stop (an update, a reboot) is no longer sealed and
  sent by the next start: it listed the scripts in upload directories found by name before
  their content was checked, raising alerts the whole snapshot withdraws.
- A failed probe logged both by a proxy and by the site behind it (often in a container) is
  looked up in that site's roots instead of being left open: when the script is not there, it
  raises nothing.

## [0.1.31] - 2026-10-29

Update the verifier, then the sensors.

### Sensor

- A failed probe logged by several proxy sites (the same path tried over http and https, each
  scheme with its own log) no longer raises an alert: requests seen in more than one log are
  judged against the sites of every one of them, instead of being left open.
- Each requested script in the log events names the host files it would be (`files`), and
  whether one exists (`file_exists`): behind a proxy, in the site answering the same name, such
  as a container's web server.
- The `._` files macOS leaves in the zips it makes are no hidden files in the data directories.
- The data files searched to their end and found free of code are remembered while unchanged:
  a host with more documents than one run can search gets through them in a few runs, and
  "Data files not searched for code" no longer comes back every hour for the same files.

### Verifier

- Log alerts give the host path of the requested script and say whether it exists, and are
  titled "Web request: ..." instead of "Log: ...".
- The Alerts page has a filter bar: severity (low notes hidden by default), server, category,
  free text (server, address, domain, path, detail) and order, kept in the page address. Alerts
  show their category as a tag and their server with a colour of its own.
- The Servers page searches servers by name, address, system, technology and domain, filters
  them by state and sorts them.
- A server's page keeps its health notes and its sensor's activity apart from its alerts.

## [0.1.30] - 2026-10-29

Update the verifier, then the sensors.

### Sensor

- A data file may hand its own functions to WordPress hooks (`add_filter('hook', 'its_function')`
  with literal arguments), as a theme registers the page layouts it keeps in the uploads; a hook
  given any other function stays code.

## [0.1.29] - 2026-10-29

Update the verifier, then the sensors.

### Sensor

- A service's private `/tmp` that goes when the service stops is no "watched directory moved
  away" event.
- A data function may take parameters: they run nothing while it is only defined.

## [0.1.28] - 2026-10-29

Update the verifier, then the sensors.

### Verifier

- A directory of the code tree where, by the complete list of changed files, only data files
  changed (a custom application writing next to its code) no longer raises "Code changed".
- A pause of the heartbeats before a signed stop (a sensor frozen, then stopped by a reboot or an
  update) raises "Missed heartbeats": the start explains only the silence after the stop
  (SEC-194).

### Sensor

- A PHP data file may define functions without parameters whose body is data, as a theme wraps
  its page layouts; any call in the file keeps it code.
- The private `/tmp` systemd and snapd give services and snaps is watched as a scratch directory
  of its own: it lies below root-only directories, deeper than the scratch depth from `/tmp`, and
  its service writes there as in `/tmp` (SEC-193).

## [0.1.27] - 2026-10-29

Update the verifier, then the sensors.

### Sensor

- A `.php` file in the uploads without any PHP tag ("Silence is golden.") is text PHP sends as it
  is, not a script.
- Each application's web root is watched in real time, without its subdirectories and for scripts
  only (SEC-173, web root part).

### Verifier

- A script that appears in a web root and is removed within fifteen minutes raises a critical
  alert: a probe that deletes itself leaves no trace in the snapshots (SEC-173).

## [0.1.26] - 2026-10-29

Update the verifier, then the sensors.

### Sensor

- The first run that hashes the content behind a release's shared link no longer reports that
  file as changed.
- A `$` or a brace in a double-quoted string is text unless it interpolates (`"$10"`), so a data
  file holding prices stays data; for the first three PHP files of the uploads found to be code,
  an issue says what made them so.
- The code manifest of an application found in the run is never removed as stale: after a week
  without reaching the verifier, the changes made meanwhile are still named (SEC-200).
- A web server started by systemd with `PrivateTmp=` or `ProtectSystem=` counts for stale
  configuration again: the host's servers are told from containers by their root, not by their
  mount namespace (SEC-153).
- Containers are read where Docker keeps them with `userns-remap`, as a snap or with
  `--data-root` on its command line, and where k3s and MicroK8s keep their tasks; a runtime
  running whose state is found nowhere is said in the issues (SEC-188).

### Verifier

- A container runtime the sensor could not read raises a medium alert (SEC-188).

## [0.1.25] - 2026-10-29

Update the verifier, then the sensors.

### Sensor

- A PHP file holding data only may open with comments and WordPress's direct-access guard (a
  theme's page layouts), and a hidden one is no finding either (a CMS's redirect map); database
  dumps are documents, whose backticks are no code.
- In the upload directories only scripts and server configuration files spend the real-time event
  budget: images or junk written by the thousand no longer push out the script written after
  them (SEC-191).
- A scratch file event repeats one of the same second only for the same inode and mode: a name
  warmed up with a harmless file no longer hides the executable written under it next (SEC-190).
- A process start whose command line the redaction shortened carries a short hash of the full
  one: two web shell commands shown alike are no longer one repeat, nor one alert (SEC-192).
- Past a thousand Docker containers the sensor reads those whose configuration changed last,
  which the daemon rewrites when it starts one, and other runtimes have a bound of their own:
  stopped containers created by the thousand no longer push a running one out (SEC-187).

### Verifier

- A container list cut at its bound raises a high alert (SEC-187).
- A command passed in a failed request for a script missing at collection time still raises an
  alert: a web shell used and deleted before the collection looks missing (SEC-196).

## [0.1.24] - 2026-10-29

Update the verifier, then the sensors.

### Verifier

- A failed request in the log of a site that answers every request itself (`return`) or hands
  it to a proxy is a probe, like one for a script missing from disk: the backend's own log
  judges what ran there. Scanners hitting the proxy of a host whose sites live in containers
  raised dozens of high alerts.

- A container with power over the host that keeps its name, tag and powers but runs another
  image raises a medium alert: a retagged image is another program with root on the host
  (SEC-189, snapshot side).

### Sensor

- A local Docker volume of type overlay is judged by the host directories its options name: its
  lower layers read, its upper one written (SEC-203).
- Sendmail started through `sh -c --`, as Symfony's mailer does (Drupal), is PHP's mail too, not
  the web server's user starting a shell.
- With short open tags the data-file search opens a block on `<?php:` and `<?xml:` (a goto label)
  and `<?php::class;`, which PHP runs (SEC-195); from that pass only named signatures count, so
  a `<?name` quoted in a log no longer turns the stack traces after it into a critical (SEC-210).
- The PHP lexer of the data-file search takes a carriage return alone for the end of a line, as
  PHP does: it closes a `//` or `#` comment and ends a heredoc's opening line, where code written
  after it ran unseen (SEC-209).
- A device given to a container through a link (`/dev/<vg>/<lv>`, `/dev/block/8:0`) is judged as the
  disk it leads to, and SCSI generic and NVMe passthrough devices (`/dev/sg*`, `/dev/ng*`,
  `/dev/bsg/`, cgroup rule `c 21`) count as disks (SEC-205).
- A container holding the socket of a daemon that acts as root for whoever talks to it (system
  D-Bus, systemd, snapd, libvirt, LXD, BuildKit), or the directory holding it, has power over
  the host like one holding a runtime socket; so has one writing `/run/systemd` (SEC-204).
- The file behind a release's link to its shared copy (`shared/wp-config.php`, `.env`) is hashed
  and inspected under the link's name: a change to it is named as a change of the application's
  code, where before nothing recorded it (SEC-197).

## [0.1.23] - 2026-10-28

Update the verifier, then the sensors.

### Sensor

- What real sites keep in their uploads and code that runs nothing is no longer reported: a
  plugin's log kept as `.php` behind an `exit`, a theme's layouts kept as a PHP file returning a
  literal array, archives and documents holding PHP (a plugin backed up as a zip) unless a
  signature names their content, the `._` files macOS leaves in a zip, a hidden PHP file that
  only sets values (a CMS's version file), hidden files that are empty or an image, a video or a
  document saved without a name.
- An image is a polyglot only with a full PHP open tag or code a signature names: the short echo
  tag turns up in compressed pixels by chance. Weak code signals are dropped in media files as
  they were in documents (a backtick in a video).

- A container's site that answers any name (`server_name _`) takes the domains of the proxy
  sites that send their requests to a loopback port the container publishes.

## [0.1.22] - 2026-10-28

Update the verifier, then the sensors.

### Sensor

- A directory of an application without a profile that is, or holds, another application (a CMS
  in `web/` of a Composer project) is not taken for a data directory because the web server owns
  it: it raised code-in-data and hidden-file alerts for the whole CMS.
- A container whose filesystem refuses `openat2` is read with the userspace resolver alone; it no
  longer switched the whole sensor to it ("Sensor guarantees reduced").
- A FUSE mount whose source is a URL (davfs2 mounts plain `fuse`) is a network filesystem.

### Verifier

- Heartbeats lost while the verifier itself restarts no longer raise "Missed heartbeats" on
  every host.

## [0.1.21] - 2026-10-28

Update the verifier, then the sensors.

### Sensor

- Web servers running in containers are read: their sites, with domain, document root, logs and
  container name, translated to host paths through the container's mounts. Hosts serving every
  site from its own nginx container showed only the host's default page.
- An application no profile describes gets its upload and data directories from their
  permissions: world-writable ones are uploads, those owned by another account than the
  application's (the web server's) hold its data.
- With a release-based deploy only the release a site serves is an application, and an upload
  directory linked to the deploy's `shared` directory is followed even when that leads to another
  volume: it was reported as a suspicious link in every release.

### Verifier

- A sensor stopping for an update no longer leaves "Collector did not complete" alerts for
  the snapshot it was collecting, and the transient unit a signed update or removal runs in is
  not a new systemd service.
- The units netplan's generator rewrites in `/run/systemd/system` at every systemd reload are
  not reported as services added, changed or disabled.
- Scratch directories left without a real-time watch (caches, private `/tmp` directories of
  services) are a low alert instead of medium.

## [0.1.20] - 2026-10-28

Update the verifier, then the sensors.

### Sensor

- An envelope sent on a kept-alive connection the verifier had just closed is sent again on a
  new connection at once. Before, it waited for the next send, and the verifier raised "Missed
  heartbeats" every few minutes on every host.
- Network filesystems (NFS, SMB, WebDAV, S3 and the like) are no longer walked by `privileged`
  or scanned by `web`. A WebDAV share mounted in a home kept both from finishing within their
  15 minutes. One mounted without `nosuid` is listed in the issues.
- PHP's `mail()` running sendmail through `sh -c`, and a framework scheduler or worker running
  its own commands through the shell, are no longer reported as the web server's user starting
  a shell.
- Upload directories are watched eight levels deep instead of four: the image styles of a CMS
  sit deeper than four and were reported as places left without a watch.
- The issue for an upload link not followed names where the link resolves.

### Verifier

- A root-owned binary in a snap's data directory (`/var/snap/<snap>/`), where cloud agents
  shipped as snaps keep their plugins, is not reported as setuid in an unusual directory; a new
  or changed one still is. A file with capabilities and no setuid bit is named for what it has.
- A cloud provider's droplet agent holding a raw socket is not reported.
- Idle ingest connections stay open three minutes, longer than the heartbeat interval, so
  sensors up to 0.1.19 no longer lose a heartbeat to a connection closed under them.

- The sensor version shown for a host is the one of its latest start: an updated sensor shows
  its new version right away instead of after its first snapshot, which can take minutes.

## [0.1.19] - 2026-10-28

Update the verifier, then the sensors.

### Sensor

- Drupal's compiled Twig templates under `sites/*/files/php/twig/` are not scripts in an upload
  directory (a file there with another shape still is, and signatures still apply);
  `.ht.router.php`, `.phpstan-baseline.php` and hidden files in Drupal's `core/` test fixtures
  are not hidden scripts.

### Verifier

- A process preloading only libraries of the system or of its own vendor's `/opt` tree (an
  agent's bundled jemalloc) no longer raises "Process with LD_PRELOAD"; files under
  `/opt/<vendor>/etc` changed since installation are configuration, not "System file modified".

## [0.1.18] - 2026-10-28

Update the verifier, then the sensors.

### Sensor

- A shell or a network tool the web server's user starts is no longer taken for a webshell's when
  cron started it, where that account also runs scheduled jobs; a crontab it planted is reported
  by the schedule rules.
- A framework's command-line entry point run from its application (`artisan`, `bin/console`,
  `bin/magento`) outside the upload directories is not a program from an unusual place.
- A process of a service systemd sandboxes, in a mount namespace of its own over the host's
  root, whose deleted executable a package upgrade replaced, is "still runs a replaced binary"
  (low), as in the host's namespace.
- In a data file that starts like a PDF, a ZIP, gzip, old Office, 7-Zip or RAR, only named code
  signatures count: the weak ones (`backtick_exec`, `dangerous_call`) appear in their compressed
  streams by chance.

### Verifier

- A collector a newer sensor brings no longer raises "has nothing to compare with" after the
  update.
- The first start of a sensor within an hour of its enrollment is low ("Sensor started for the
  first time"); "Server enrolled" is medium.
- Package files under `/var` rewritten by the programs that use them (a PEAR channel registry)
  no longer raise "System file modified".

## [0.1.17] - 2026-10-28

Update the verifier, then the sensors once more by hand (`tripwatch-sensor -update`): from this
release on, sensors update and remove themselves on the verifier's order.

### Sensor

- An update order from the verifier, signed with its CA key, makes the sensor install that
  release when it is newer, in a transient systemd unit (`-apply-update`), checking the file
  against the hash signed in the order rather than the release's own `SHA256SUMS`.
- A revoked host's sensor, given an order naming it and signed the same way, removes itself in a
  transient unit (`-apply-uninstall`): package purged, or service, unit and binary removed; then
  `/etc/tripwatch` and `/var/lib/tripwatch`.

### Verifier

- The servers page offers to update every sensor older than the verifier to its release; the
  order, with the hashes of the release's sensor files, is signed with the CA key and given to
  sensors in the answers to their envelopes (`Tripwatch-Update`).
- A revoked host is refused with an order to remove itself (`Tripwatch-Uninstall`).

## [0.1.16] - 2026-10-28

Update the verifier.

### Verifier

- The servers page lists every web application grouped by framework and version, stacks first,
  with how many of each (`laravel 10.48.28 ×3`); the server's page lists them all with path and
  sites. Applications no site of the host's web server points to are no longer labelled as not
  served: a server in a container or behind a proxy serves them all the same.

## [0.1.15] - 2026-10-28

Update the verifier, then the sensors (`tripwatch-sensor -update`).

### Sensor

- The addresses of container bridges and virtual links (`docker0`, `br-*`, `veth*`, `cni*` and
  the like) are no longer reported among the machine's addresses.

### Verifier

- Each server shows the address its sensor connects from, recorded once its client certificate
  is checked: on clouds with NAT, the public address that no interface of the host holds.

## [0.1.14] - 2026-10-28

Update the verifier, then the sensors (`tripwatch-sensor -update`).

### Sensor

- Each log event names whether the script it requested exists in the document roots of the nginx
  or Apache sites writing that log (`on_disk`: `present` or `missing`), left open when the
  request may reach a proxy, a root holds a variable, a mapping is not modelled, or the server
  is Caddy.
- When the budget for searching data files for code runs out, the web result names the files
  left unsearched and the five that spent the most of it, with their owners
  (`code_search`), instead of only an issue line.
- The `apps` collector lists the code kept in the database (`db_objects`): the schema's
  triggers, stored routines and scheduled events on any framework, and on Magento integrations,
  admin and integration API tokens, layout updates, email templates and customers whose names
  carry template code. Each comes with a hash computed by the database server, never its body,
  token value or the customer's name; `db_objects_read` names the kinds actually read.
- A code manifest that cannot be written is reported as an issue with its reason, instead of
  silently stopping the naming of changed files; a code file too large to hash is named as
  modified when its fingerprint (size, change time, inode) changes between two runs; manifests
  not rewritten for seven days are removed from the state directory.
- Container mounts carry where their source leads when it goes through links (`resolved`), and
  Docker volumes whose local driver binds a host path or device are listed as mounts of that
  path (`volume`); device cgroup rules granting access are collected (`device_rules`). A
  container with the host's root under a volume or a link, a system directory below the ones
  listed before (`/etc/cron.d`, `/root/.ssh`, `/var`), a disk named `vd`, `xvd`, `dm-`, `loop`
  and the like, a cgroup rule for block devices or memory, or a runtime socket elsewhere than
  its usual path (or a directory holding one) now counts as having power over the host.
- A running container's process mount table (`/proc/<pid>/mountinfo`) is matched to the host's
  and listed as `kernel_mounts`, which add powers to those of the configuration and never take
  one away: a link swapped around the start, a link in the image or a chroot no longer hides
  the host's root, and a table that cannot be read is reported (`kernel_unverified`). The
  real-time watcher reads a container again when its configuration is rewritten at the start,
  with a budget apart from new containers. Mounts, devices, capabilities and security options
  past the 64 read keep those that give power first, and a cut list is named (`cut`) and counts
  as a power.
- The search for PHP in data files follows code interpolated in strings, commands and heredocs
  (`{$...}`, `${...}`), so a quote or `?>` inside an interpolation no longer ends the block,
  and also reads the content as PHP does with short open tags on (`<?` followed by anything).
- An upload or data directory linked into the directory holding a deploy's releases is followed
  from any application, as from a served copy whose uploads link to `deploy/shared`; until now
  such a site's uploads were left unscanned. A directory several applications reach is scanned
  once a run, served applications first, instead of once per release, which spent the budget for
  searching data files for code; upload directories reached through a link are given to the
  real-time watch by their real location. An index file in an upload, cache or `wp-content`
  directory no longer makes an application of its own.
- An application's version is also read from `composer.lock` (Laravel, Symfony, Magento) when
  the version file under `vendor/` is missing, as when dependencies live in an image.
- Log rules on Magento's REST and customer routes also match them behind the front controller
  (`/index.php/rest/...`), and `<?` followed by a blank counts as PHP in a request.
- Skimmer search: changed scripts are counted and kept apart from other changed files; past 50
  at once only generated bundles and packages updated as a whole (more than 10 scripts) are left
  out, and named in the issues, instead of every file; field names hidden in `atob` literals or
  escapes are decoded; files over 4 MB are read in pieces instead of skipped; an SVG `script`
  element with a namespace prefix counts.
- New log rules: a cart item added through the REST API and then a fetch from
  `media/custom_options` by the same address (`cart_upload_then_fetch`, high on success), a
  `file_info` parameter on a cart item (`cart_item_file_upload`), a shipping estimate for a
  guest cart ID the shop never hands out (`shipping_estimate_probe`), PHP code in the path, query
  or user agent (`php_code_in_request`), all medium, and HTTP libraries such as
  `python-requests` as user agent (`scripted_user_agent`, low). PHP code in a parameter is kept
  in the evidence, and route segments made only of words (`estimate-shipping-methods`) are no
  longer masked as tokens.
- The processes collector lists the names of the host's kernel threads (`kernel_thread_names`,
  reduced to their family: `kworker`, `kswapd`, `scsi_eh_`), at most 512.
- Real-time watch: the places left unwatched are listed up to five per class, so scratch
  directories anyone can fill no longer crowd out an upload or system gap; the event of a
  watched root moved away is never dropped as upload noise; overflows of the kernel queue a
  second apart no longer put off the replan that watches a moved root again.
- A scratch file rewritten in a loop spends the second's budget once: the repeats are put off
  and the file is looked at once more a second later, so one account rewriting the same files
  no longer uses up the budget every other account's files share.
- New `containers` collector: Docker containers read from the daemon's state directory, and
  those of containerd (Kubernetes included), Podman and CRI-O from their OCI bundles, with
  their image and what gives them power over the host (privileged mode, capabilities, host
  namespaces, unconfined profiles, devices, host directories and runtime sockets mounted),
  never their environment.
- Real-time watch of containers: the state of Docker, containerd, Podman and CRI-O is listed
  every second, and a container that appears with power over the host is reported at once
  (`container` events), with its removal. Containers already there, plain ones and redeploys of
  a known one are not.

### Verifier

- Medium log events aimed at an application's own weak points (shipping estimate for a made-up
  cart, PHP in a request, file attached to a cart item, POST to a static file) raise one medium
  alert a day per rule and log, shown and not mailed; until now only critical and high log
  events reached the operator.
- The servers page lists every web application a site serves, with its version, and counts
  the others found on disk; the host page lists both groups, served ones with their sites.
- A request that failed for a script missing from the server (`pentest_proof_*.php` answered
  404, `/tmp/phpinfo.php` answered 502) no longer raises "Log: script in upload path" or the
  other log alerts: no code ran. A script that exists stays serious whatever its status, and
  the alert says it exists. Until the sensors are updated nothing changes.
- "Data files not searched for code" (high): files stuffed with code that spend the run's budget
  can no longer hide a payload behind them in silence; the alert lists the unsearched files and
  the ones that spent the budget.
- New or changed database objects raise an alert (critical for a trigger on orders, quotes,
  payments, customers, settings or users; medium for an email template); a layout update or
  email template holding PHP or an executing call is critical on its own, template code in a
  customer's name high. A kind read for the first time is not compared, so updating the sensor
  does not turn every existing object into an alert.
- An existing administrator whose name, email or active flag changed raises a high alert.
- Text from the monitored host can no longer forge lines of the alert email or reverse how a
  name reads: line breaks (in titles), control characters, line separators and invisible
  format characters (bidirectional overrides, zero-width marks) are stored as visible escapes,
  and invalid UTF-8 as U+FFFD. The interface isolates the bidirectional text of the alerts
  already stored.
- A program that takes the name of one of the host's kernel threads (`kauditd`, `ksmd`,
  `rcu_sched`, `xfsaild/sda1`), as its name or as `[name]` on its command line, is a critical
  "Process disguised as a kernel thread" like the usual names already were; the watchdog daemon
  stays out.
- "Watched directory moved away or removed" alerts are grouped by class and path: one upload
  directory moved again and again no longer fills the group a system directory shares.
- "Container with access to the host" (high): a Docker container that appears with a power
  that amounts to root on the host. A redeploy of one already there (same name, image and
  powers, such as a reverse proxy holding the Docker socket) raises nothing.
- The same alert is raised as soon as the sensor reports the container's start, with the same
  fingerprint and detail: a container started to escape and removed before the next snapshot
  is no longer missed, and the snapshot that follows adds nothing.
- Alert emails are sent as quoted-printable: a path of any length no longer makes a line over
  998 bytes that a relay could bounce after accepting the message.

## [0.1.13] - 2026-10-28

Only the sensor's behaviour changes. Update the verifier to keep the versions aligned, then the
sensors (`tripwatch-sensor -update`).

### Sensor

- The scriptlets rpm writes to `/var/tmp` as `rpm-tmp.XXXXXX` and runs while installing or
  upgrading a package no longer raise "A program started from /var/tmp", under the same
  conditions as apt's debconf scripts: root, a root-owned file, started by rpm or a package
  manager built on it, known by its executable, UID and command line.
- Large PDFs and other binary files in data directories no longer raise "Code inside a data
  file" with `backtick_exec`: binary data holds `<?=` and backticks by chance, but the blocks it
  makes hold control bytes PHP 8 refuses to compile, so their weak signals (`backtick_exec`,
  `dangerous_call`) are dropped; named signatures still count, and `__halt_compiler` ends a
  block so binary data appended to a payload cannot hide it. The alerts already raised stay
  open (critical alerts are never resolved automatically): resolve them by hand.
- Directories deeper than the real-time watch below a directory only root can enter (root-owned,
  no search permission for group or others, like snapd's `/tmp/snap-private-tmp/snap.*`) no
  longer raise "Places left without real-time watch": no other user can reach them.

## [0.1.12] - 2026-10-28

Update the verifier, then the sensors (`tripwatch-sensor -update`). This release fixes how
0.1.10 and 0.1.11 lowered the alerts around a stopped sensor; until the sensors are updated,
their stops are judged as stops on a running system.

### Sensor

- The debconf configuration script apt extracts to `/tmp` and runs before installing a package
  (`/tmp/nginx-common.config.HSv41h`) no longer raises "A program started from /tmp": only when
  root runs a root-owned file of that name, started by the system's perl running
  `/usr/sbin/dpkg-preconfigure`, known by executable, UID and command line, not by process name.
- A script linked to its copy at the same path in the deploy's shared directory
  (`releases/5/wp-config.php -> ../../shared/wp-config.php`, the linked files of Capistrano or
  Deployer) is no longer a suspicious link, when the copy is a regular file outside the upload
  and data directories and carries no webshell signature.
- A process start identical to one reported in the last hour (same reason, executable, script,
  parent, users, directory and command line) is counted instead of sent: an account that is
  also the web server's user and runs jobs every minute filled the verifier's daily budget for
  uploads and process starts. Anything that differs is still reported at once.
- Card skimmers: scripts, templates and SVG images changed since the previous snapshot are read
  for payment fields sent to another host or hidden behind obfuscation, and for live secret
  payment keys (`payment_skimmer`, critical); SVG images that run script in upload directories
  are reported (`active_svg_in_upload_dir`). The detection benchmark keeps the sensor's state
  from the baseline, as on a server.
- New webshell signatures: includes of request input, of a URL or of `php://input`, `eval` of
  fetched content, calls through `$GLOBALS`, and dangerous function names written so that they
  do not appear in the source (pieces, escapes, `chr()`, XOR). The `preg_replace` `/e` signature
  now checks that the delimiters match, which removes false positives on ordinary patterns.
- With `-state-dir`, the web collector keeps a manifest of each application's code files and
  names the files added, changed or removed since the previous delivered snapshot; the verifier
  raises each script added or changed (high) and lists the files of a directory that changed.
- The web collector reports PHP saved in an application's data files (sessions, logs, error
  reports, caches) to be included later (`code_in_data_file`, critical): a real open tag
  followed by a webshell signature or a dangerous call. A request logged with its spaces
  encoded, or a template snippet without such a call, is not reported.
  Each block runs to the `?>` PHP itself sees (not one inside a string, a heredoc or a comment),
  the short `<?` tag, commands in backticks and `getallheaders()` count, and data files over 4 MB
  are read through by a lexer that keeps its state from one piece to the next, within a budget
  of bytes a run.
- A snapshot that cannot be sealed because an earlier envelope is still pending is sent again
  every 10 seconds for five minutes, without collecting it again, instead of an hour later.
  Event batches go out at most one every two seconds, the pace the verifier accepts.
- Each event batch takes the system events first, then the others, then the noise of the
  uploads, so a change to root's keys is not held behind a flood; at a stop, what the final
  burst cannot send is counted as lost in a last batch.
- Events in the homes and crontabs of accounts other than root are marked with the account and
  rank below root's system paths, with at most 64 queued for each account before they count as
  noise; an event that has waited 15 seconds goes before later ones of a higher rank. An account
  flooding its own `~/.ssh` can no longer delay or evict root's keys, nor a webshell. The
  `.ssh` directory itself belongs to its home, and a file in the cron and at spools belongs to
  the account of its UID, never to its name.
- Root's events reach the batcher through a channel of their own, read first, so another
  account flooding the shared one can no longer have them dropped; a loss there counts in
  `dropped_system`. Adding an event to a full queue costs the same whatever the queue holds.
- The root of a watched place moved away or removed is reported at once and watched again within
  seconds when it is back; after the kernel's event queue overflows, the watches are planned again
  from scratch. Every few seconds the sensor also checks that each root is still the directory at
  its path, so a root moved within a watched parent (`/etc/sudoers.d`), one replaced under its name
  by an ancestor moved aside and recreated, one whose watch could not be placed or one back after
  a long while is reported and watched again too, and the old inode's watches no longer report
  under a path that is another directory's. Two directories swapped in one call are watched again
  under their right names, and the events budget of the uploads is now separate from the scratch
  directories' one.
- A watched directory renamed within the watched places keeps reporting under its new name, its
  subdirectories with it; one moved out of them has its watches removed from the kernel. Before,
  a rename (an upload directory, a unit's drop-in directory) left the directory silent until the
  next snapshot and its watch held by the kernel.
- The packages collector reports, for each dpkg package, its version and a digest of the
  checksums recorded for it (`states`).
- The exemption for an account's own scripts is narrowed: the path is normalised, and only a
  job run by cron, from the account's home, from a file the account owns, outside every upload
  directory, is exempted. Python and Ruby application servers (gunicorn, uwsgi, puma, unicorn,
  Passenger) count as the web server.
- A process still running a replaced binary is marked as packaged (`exe_packaged`) only when
  dpkg's file lists name the path; only then is it a "restart pending".
- The uploads have a budget of their own too (6,144 watches), also for directories created
  later, so a web user filling them leaves room for the system and the homes.
- The scratch directories come last and have a budget of their own (512 watches, two levels
  deep): directories anyone creates there can no longer take the watches of the system, the
  homes or the uploads. Places of those left unwatched by the bounds are listed in each snapshot.
- Files in the scratch directories are marked when the web server's user owns them; at most
  4,000 events a second are handled there, and 1,000 for each owning account, so one account's
  files cannot hide another's; the rest is counted as lost; the executables remembered
  there are pruned by age.
- The scratch directories (`/tmp`, `/var/tmp`, `/dev/shm`, `/run/lock`) are watched for executable files: a
  dropper written, run and deleted lives too briefly for its process to be read, but its file
  is seen. Only executables, and the removal of those, are reported.
- The stop event says whether systemd was shutting the system down (`systemctl
  is-system-running` answering `stopping`) and whether the stop is for an update: the package's
  post-installation script and `-update` leave a marker before restarting the sensor.

- Events on files outside the uploads carry the content the sensor last knew them to have
  (`prev_sha256`), read from the keys files when the watch starts.

### Verifier

- Alert groups whose titles share only part of a word ("Cod" of two titles) or only the root of
  a path ("A program started from /") are named after their lead alert or the last whole word.
- A process started by the web server's user raises one alert per command (executable, parent,
  user, directory and command line), no longer one per shell. Where that account also runs
  scheduled jobs, each job can be accepted as legitimate on its own; before, accepting one was
  undone by the next different command of the same shell.
- A gap between heartbeats with a start of the sensor in it no longer raises "Missed heartbeats":
  the start already judges that silence from what the sensor signed as it stopped, so a server
  switched off at night shows one low "Server was off" instead of a medium alert as well.
- Security fix: the page asked for before signing in is followed only when it is a path on the
  console. A tab or a control byte in it (`/%09/evil.example/`), which browsers drop, could send
  the operator to another host after the login.
- A process of user space named like a kernel thread (`[raid5wq]`, `kswapd0`, `kworker/0:2`)
  with an executable raises a critical alert: real kernel threads are never listed, and titles
  that only use brackets, such as celery's, are not matched.
- Security fix: an enrollment records the host's new certificate in the same statement as its
  key, and a host with no certificate recorded accepts none. Before, the first certificate
  presented after a re-enrollment became the host's, so a copy of the old bundle could win
  against the new sensor. Hosts enrolled before certificates were recorded must be enrolled
  again.
- Events marked with an account other than root have a daily budget of their own (20,000 a
  host, 2,000 for each account): a user flooding their home no longer uses up the budget of
  root's changes, which kept a key written and removed in two batches from being raised. The
  budgets are counted in one query per batch, and a batch naming more than 64 new accounts keeps
  the events of the first 64 only.
- Heartbeats and event batches are rate limited per host (a burst of 60, then one a second),
  refused before the body is read; each path's event history is read once per batch.
- The ingest endpoint speaks HTTP/1.1 only, as the sensors do, with write and idle timeouts
  and a 16 KB header limit.
- `tripwatch-verifier enroll` validates the host name as the console does and refuses to enroll
  an existing host again without `-replace`.
- User emails are stored and looked up in lower case everywhere: a password reset from the
  command line with capitals no longer creates a second user and leaves the first working.
- Checksums of a dpkg package that changed while its version did not are a high "Package
  checksums changed without an upgrade", package by package, whatever else changed in the
  database at the same time.
- Review of the 0.1.11 false-positive fixes, so that none opens a way around detection: a POST
  to a script in the uploads answered with a redirect stays high; nginx's configuration counts
  as read at its newest workers, Apache's and Caddy's at their oldest process; shared executable
  mappings of real files (memfd ones included) count again, only the anonymous region of OPcache
  and JITs is left out; new generators and set-user-ID programs are high again whatever packages
  did; removing an activation link (a unit disabled) is low.
- Lost real-time events are one alert a day, not a single one kept open for good.
- A watched directory moved away or removed is a high alert (medium for the scratch
  directories): moving it away and back blinds the watch on it until it is placed again.
- Places left without a real-time watch are an alert per class: high for the system, the homes
  and the uploads, medium for the scratch directories. The list is computed again at each
  snapshot.
- An executable file in a scratch directory is high when root or the web server's user owns it,
  medium otherwise (builds and installers); one that appears and is removed within 15 minutes is
  critical for root and the web server's user, high otherwise. Each account's drops are a group
  of their own, so one user's noise never folds another's alerts into an aggregate. The benchmark's dropper run and deleted between two checks is caught.
- An SSH keys file that existed long before, changed and put back within 15 minutes, is the
  critical "SSH keys changed and put back" it should be; before, the original content had to be
  within the window. Transient alerts are distinct by the time they appeared, so the same key
  or webshell reused later raises a new alert and email.
- Security fix for the nightly shutdown handling of 0.1.10 and 0.1.11: severities are lowered only
  on what the sensor signed. A stop on a running system keeps the silence critical and the next
  start high, even after a reboot ("Sensor stopped before a reboot"); a new boot without a clean
  stop is high; another version on the same boot without an update is high ("Sensor replaced
  without an update"). Only a signed shutdown followed by a new boot is a low "Server was off",
  and only a stop for an update followed by a new version a low "Sensor updated".

## [0.1.11] - 2026-10-23

False positives seen on a real server, fixed. Update the verifier, then the sensors
(`tripwatch-sensor -update`): some fixes need both. Alerts already open from the earlier rules
stay open until closed by hand.

### Sensor

- Only private executable mappings are reported: shared ones are what OPcache's JIT and other
  JITs map, a shared anonymous region showing as `/dev/zero (deleted)`.
- A process whose deleted executable has been replaced by a new file at the same path is marked
  as such (`exe_replaced`): a package upgrade it was not restarted for.
- A program or script run by an account from its own home is no longer reported as started from
  an unusual place (a crontab calling a script in the deploy user's home); the same file run by
  another account, by root or by the web server's user still is.
- The packages collector fingerprints dpkg's list of installed versions apart from the
  checksums (`status_sha256`).
- A web server's configuration counts as stale only if it changed after the server last read it:
  a reload starts new workers while the master keeps running.

### Verifier

- A process still running a replaced binary in the system's directories is a low "restart
  pending"; one whose binary is gone stays high. Shared anonymous regions reported by older
  sensors are ignored.
- "Package database changed without installations" no longer follows every upgrade: with
  sensors from 0.1.11 on dpkg hosts, an upgrade (the installed versions changed) raises
  nothing, and checksums or file lists changed while no version did raise a high "Package
  checksums changed without installations".
- Real-time events in systemd's directories count only for files systemd loads (units,
  drop-ins, generators): the temporary names of atomic writes no longer raise alerts, and
  removing a service or a scheduled task raises none. Uninspected process starts are low.
- A new generator or set-user-ID program in the system's directories is medium, not high, when
  packages were installed or upgraded since the previous snapshot.
- A script requested in an upload directory and answered with a redirect is low: the redirect
  is the server's own (to https, to a canonical host) and the request that follows is judged on
  its own status. Any other status but success stays high.

## [0.1.10] - 2026-10-23

Update the verifier; the sensors stay on 0.1.9.

### Verifier

- Each sensor start is judged against how the previous run ended, from the system boot it
  reports: a new boot after a clean stop is one low "Server was off" event, a new version on the
  same boot a low "Sensor updated", a new boot without a clean stop a medium "Server restarted
  without a clean stop"; the same boot and version, a service restarted by hand, stays a high
  "Sensor restarted without a reboot". A plain stop raises nothing by itself, and the silence
  that follows it is medium for a day, then high. A server switched off every night no longer
  raises three alerts a day. Starts seen before this version are read back from their alerts.

## [0.1.9] - 2026-10-23

Update the verifier first, then the sensors (`tripwatch-sensor -update`): a verifier older than
this ignores the real-time events and the new collectors. The sensor's systemd unit gains
`CAP_NET_ADMIN`, which the packages install with the new unit; a unit copied by hand has to be
replaced. The first snapshot after the update runs the new rules on what is already there:
modules built outside the kernel's tree, packet sockets of monitoring agents and native modules
mapped from web roots show up then, and can be accepted once.

### Sensor

- **Real-time events.** Between snapshots the sensor watches with inotify the account
  databases, sudo, polkit and doas, the SSH server configuration and every account's
  `authorized_keys`, cron and `at`, systemd units and generators, library preloading, start-up
  scripts and the upload directories of the web applications, and sends each change within two
  seconds with the file's size, SHA-256, owner and mode. From the kernel's process connector it
  reports only the process starts that matter: the web server's user starting a shell, an
  interpreter or a network tool; programs and scripts run from `/tmp`, `/dev/shm`, homes and web
  roots; programs deleted after they started; root gained through a set-user-ID program outside
  the system's directories.
- Events travel in signed event envelopes of the same chain, in bounded batches with the count
  of what was lost and whether a package manager was running; they wait in a bounded queue while
  the verifier is unreachable. Each snapshot says whether the watchers run, and why not.
- `tripwatch-sensor -watch-only` prints what the watchers report, without a verifier.
- Hardening of the watchers after a security review: a link in a watched directory is never
  followed, and no device is ever opened while reading file attributes (`O_NOCTTY` everywhere,
  attributes read only from regular files and directories), so a terminal planted by the web
  server's user can no longer become the sensor's controlling terminal; hashing is bounded to
  files up to 1 MB and 16 MB a second, with a budget of its own for root's files; a package manager is recognised by a lock only root can
  hold, not by a process name; upload noise is dropped before system events when the queue is
  full; what is queued at a stop is sent before the stop event; directories left unwatched by
  the bounds are reported; `CAP_NET_ADMIN` is given up right after subscribing to process
  events.
- A new `kernel` collector: modules from both of the kernel's lists with their place in the
  module tree, taint and lockdown, processes hidden from `/proc`'s listing (every PID the kernel
  may have handed out is probed, within ten seconds), eBPF programs held by processes, pinned
  BPF objects and dynamic kprobes.
- The `sockets` collector also reports packet (`AF_PACKET`) and raw sockets, with the
  executable of the process that holds each.
- The `processes` collector reports the process tracing each one with ptrace and the
  executable mappings of memory-only files, of files under scratch directories, homes and web
  roots, and of files deleted outside the system's library directories.
- A sensor that stops sends a last signed event saying so, and whether its package is being
  removed: the package's pre-removal script leaves a marker the running sensor reads.

### Verifier

- Events are kept for seven days, at most 20,000 a server in 24 hours for what the web server's
  user can produce and as many again for system paths, and judged at once (events over the
  quota still count for the rules within their batch).
  Critical: the web server's user starting a shell or a network tool, root gained through an
  unknown set-user-ID program, changes to sudo or polkit rules and to `ld.so.preload`, and what
  no hourly snapshot would show: a script appearing in the uploads and gone within 15 minutes,
  an SSH key file written and removed or changed and put back. High: scripts and `.htaccess`
  files in upload directories, SSH keys and server settings, services, scheduled tasks,
  start-up scripts, programs run from unusual places or deleted after start. Changes to
  services, scheduled tasks and start-up scripts made while a package manager runs are one
  severity lower. Lost events are an alert of their own, high when system events were among
  them. A file's content is part of an alert's fingerprint, so an acknowledged alert does not
  absorb a later, different change to the same file.
- Each server's page lists its latest events, and its System block says whether files and
  processes are watched.
- Kernel rules: a module hidden from either list, a process hidden from `/proc` and an eBPF
  tracing program held by a program from an unusual place or a deleted one are critical; a
  module outside the module tree, a module loaded with out-of-tree or unsigned taint, new taint
  flags of that kind and new kprobes are high; new eBPF programs and pins are medium.
- A packet or raw socket held by a program from an unusual place or deleted is critical, by a
  program other than the known capture and network tools high, by no listed process medium.
- Fileless processes (run from `memfd`) and code mapped from memory-only files or scratch
  directories are critical, code mapped from homes, web roots or deleted files high. A process
  traced by something other than a known debugger is high, critical when it is sshd, su, sudo
  or another holder of secrets, or when the tracer is unknown or out of place.
- "Sensor removed" (high) when the sensor package is uninstalled, "Sensor stopped" (medium)
  when the service stops, by hand or for a reboot.
- The benchmark runs the sensor's watchers during each scenario and judges what they report with
  the verifier's rules.

## [0.1.8] - 2026-10-23

Update the verifier first, then the sensors (`tripwatch-sensor -update`).

### Sensor

- Each snapshot carries the machine's system: distribution and version (`/etc/os-release`),
  kernel, architecture, hostname, boot time, CPUs, memory, the addresses of its network
  interfaces (loopback and link-local left out) and the sensor's version. Values are bounded:
  they come from files the host writes.

### Verifier

- A **Servers** page lists the fleet: system and kernel, sensor version flagged "update
  available" when older than the verifier (with `tripwatch-sensor -update`), addresses, web
  applications, last heartbeat and snapshot, alerts; revoked servers apart. A sensor that does
  not send its system yet still shows its version, read from the signed event of its start.
- Each server's page has a System block: the facts above plus package manager and count,
  listening ports and web applications. The overview's server cells show the sensor version.

## [0.1.7] - 2026-10-23

Update the verifier; the sensors stay on 0.1.5.

### Verifier

- A script in an upload directory is critical when its content carries a webshell signature,
  and high when it carries none: some applications keep generated templates there. The alert's
  detail is unchanged, so acceptances given before keep holding; an accepted file that changes
  is raised again.
- Beyond the cap of 100 open alerts per rule on a server, the rest is held in an aggregate
  ("Many alerts of the same rule"). That aggregate now joins its group, which says
  "+ more held back"; accepting or resolving the group closes it too, and the alerts it held are
  raised one by one with the next snapshot instead of seeming to come back.

## [0.1.6] - 2026-10-23

Update the verifier; the sensors stay on 0.1.5.

### Verifier

- Revoked servers no longer count in the overview: they are left out of the figures, the charts,
  the server cells, the healthy count and the alarm mark, and named apart under Servers. Their
  pages keep their alerts as a record.
- Every row of Top rules and Web attacks opens the latest alert it comes from. Web attacks count
  the requests each alert reports rather than how often the alert was seen, and read the source
  address of alerts raised before 0.1.3, whose detail is in Italian.

## [0.1.5] - 2026-10-23

Update the verifier and the sensors.

### Sensor

- rpm hosts are verified like dpkg and apk ones: the sensor reads the rpm database directly,
  Berkeley DB (RHEL/CentOS 7 and 8, Amazon Linux 2) or SQLite (RHEL 9, Amazon Linux 2023,
  Fedora, including transactions still in the write-ahead log), and reports system files that no
  longer match their package. Files rpm itself leaves out of verification (`%ghost`,
  `%verify(not md5)`, languages and documentation not installed) are skipped. Until now every
  dot-file under `/usr` on these hosts (`.hmac` checksums of crypto libraries, `.build-id`,
  manual pages) was a "Hidden entry in /usr" alert, because no package database was read.
- Hidden entries under `/usr` are no longer searched in source trees (`/usr/src`,
  `/usr/local/src`) and language package trees (`node_modules`, `site-packages`,
  `dist-packages`), where checkouts and packages ship `.git`, `.github` and CI files. Unowned
  subdirectories of a packaged hidden directory (rpm lists the `.build-id` links, not the
  directories holding them) are walked instead of reported; files added there still are.
- An upload directory that is a link to a directory inside the application or its deploy
  directory (`releases/5/uploads -> ../../shared/uploads`) is no longer a "Suspicious link": it
  is the usual layout of release-based deploys, and its content is still scanned. A link leading
  anywhere else, or named like a script, is still reported.

### Verifier

- The overview is an operations dashboard, dark slate by default (light and system themes stay
  in the menu):
  - a strip of figures for open critical, high, medium and low alerts and silent sensors, each
    with what arrived in the last 24 hours, the age of the oldest and the last 7 days' trend;
  - alerts raised over the last 24 hours or 7 days, in columns stacked by severity;
  - the servers as cells with their worst alert, heartbeat and snapshot, silent ones hatched;
  - open alerts grouped by rule across servers, the first 10 groups with a link to the rest;
  - top rules of the last 7 days, unresolved alerts by server, and the sources and targets of
    the attacks seen in the web server logs.

  Every figure comes from the alerts and hosts the verifier holds; charts are SVG drawn by the
  server, with no script. The side panel stays on the Alerts page.
- Closed groups of alerts stayed open on narrow screens; they now stay closed.

## [0.1.4] - 2026-10-23

Update the verifier and the sensors.

### Sensor

- `sudo tripwatch-sensor -update` installs the latest release in the same form as the installed
  one (`.deb`, `.rpm` or static binary) for the server's architecture, after checking it against
  the release's `SHA256SUMS`, and restarts the service. Nothing changes if the running version is
  already the latest.

### Releases

- The sensor's packages and binaries are also published under fixed names
  (`tripwatch-sensor_amd64.deb`, `tripwatch-sensor.x86_64.rpm`, `tripwatch-sensor_linux_amd64` and
  the arm64 equivalents), so `releases/latest/download/` always gives the newest one and the
  install commands in the README no longer name a version.

### Verifier

- Interface redesign in the same control-room direction, after a design review:
  - IBM Plex Sans and Mono embedded in the binary, one type scale, section titles above body
    text, clearer button hierarchy;
  - the overview's rows carry no buttons; actions live in the side panel and on each alert's
    page, where Acknowledge is the primary action, and in long lists they show on the row being
    pointed at;
  - "Accept as legitimate" only on an alert's page, with what it does, or for a whole group;
  - resolving or accepting a group of critical or high alerts asks once more with their number;
  - each row of a group shows the file or item that tells it apart;
  - the side panel puts a silent sensor and planted web code ahead of other alerts of the same
    severity, and comes before the tables on smaller screens;
  - new mark, a tripwire cut in the middle, in ink; the wire and the browser tab icon turn red
    while a critical alert is open;
  - email not configured shows as a warning in the menu; the running version is shown;
  - contrast of red and muted text raised above 4.5:1 in both themes, larger touch targets.

## [0.1.3] - 2026-10-23

Update the verifier; the sensors stay on 0.1.2.

### Verifier

- The interface, the alerts and the emails are in English. Alerts raised by earlier versions
  keep their Italian text until the condition is raised again; conditions whose fingerprint
  carried an Italian description of a file's owner and mode are raised once more under the
  English one, and an acceptance of such an alert has to be given again.

- Every alert page has **Copy for an AI assistant**: the alert in Markdown (what tripwatch is,
  the alert's facts, the collected detail fenced as data, and the question to answer), ready to
  paste into an AI chat.
- A privilege policy file or directory writable by someone other than root is explained in plain
  words: who can write it (every user, a named group and its members, an account, an ACL), why
  that gives root, and the usual fix. The raw owner and mode close the text.

## [0.1.2] - 2026-10-23

Update both the verifier and the sensors.

### Sensor

- Hidden scripts that libraries ship on purpose are no longer reported as hidden: the
  `.php_cs.php` and `.php_cs.dist.php` tool configurations, and hidden files inside the test
  directories of a dependency (`vendor/`, `node_modules/`, `bower_components/`, under `tests/`,
  `test/`, `fixtures/`). Webshell signatures are still searched in them.

### Verifier

- **Accept** an alert, or a whole group, as legitimate. A resolved alert whose condition is still
  present comes back with the next snapshot; an accepted one is not raised again while its
  evidence (for a file, its size and SHA-256; for a process, its executable and hash) stays the
  same, and comes back as soon as it changes. The server's page lists what was accepted and puts
  it back under watch. Silences, broken chains, sensor events and the verifier's own alerts
  cannot be accepted.

### Documentation

- The verifier's compose defaults to the `latest` image; pinning a release is documented as the
  way to decide when to update.

## [0.1.1] - 2026-10-23

Update both the verifier and the sensors.

### Sensor

- Hidden entries under `/usr` that a package installed (kernel headers, `.build-id`
  directories) are no longer reported. Anything added inside such a packaged hidden directory
  still is. Alerts already raised for them stay open until resolved by hand.

### Verifier

- Alerts of the same rule, host and severity are one row that opens onto them, with actions
  that acknowledge or resolve the whole group. An open group stays open across the automatic
  refresh.
- The enrollment page asks for the server's system (Debian/Ubuntu, RHEL family, or sensor
  already installed) and gives one command that downloads the sensor package of the verifier's
  own release for the server's architecture, installs it, removes the download, enrolls the
  server and starts the sensor.
- The enrollment command uses `sudo`.

### Documentation

- README with a table of contents, a dedicated installation section, and how to learn about new
  releases, check installed versions, update and remove.

## [0.1.0] - 2026-10-23

First public release.

- Sensor as `.deb` and `.rpm` packages for amd64 and arm64, and as static binaries.
- Verifier as a multi-arch container image on GHCR, with its `docker-compose.yml` and
  `verifier.env.example` attached to the release.
- Build provenance attestations for every file and for the image.

[Unreleased]: https://github.com/cpibia/tripwatch/compare/v0.1.42...HEAD
[0.1.42]: https://github.com/cpibia/tripwatch/compare/v0.1.41...v0.1.42
[0.1.41]: https://github.com/cpibia/tripwatch/compare/v0.1.40...v0.1.41
[0.1.40]: https://github.com/cpibia/tripwatch/compare/v0.1.39...v0.1.40
[0.1.39]: https://github.com/cpibia/tripwatch/compare/v0.1.38...v0.1.39
[0.1.38]: https://github.com/cpibia/tripwatch/compare/v0.1.37...v0.1.38
[0.1.37]: https://github.com/cpibia/tripwatch/compare/v0.1.36...v0.1.37
[0.1.36]: https://github.com/cpibia/tripwatch/compare/v0.1.35...v0.1.36
[0.1.35]: https://github.com/cpibia/tripwatch/compare/v0.1.34...v0.1.35
[0.1.34]: https://github.com/cpibia/tripwatch/compare/v0.1.33...v0.1.34
[0.1.33]: https://github.com/cpibia/tripwatch/compare/v0.1.32...v0.1.33
[0.1.32]: https://github.com/cpibia/tripwatch/compare/v0.1.31...v0.1.32
[0.1.31]: https://github.com/cpibia/tripwatch/compare/v0.1.30...v0.1.31
[0.1.30]: https://github.com/cpibia/tripwatch/compare/v0.1.29...v0.1.30
[0.1.29]: https://github.com/cpibia/tripwatch/compare/v0.1.28...v0.1.29
[0.1.28]: https://github.com/cpibia/tripwatch/compare/v0.1.27...v0.1.28
[0.1.27]: https://github.com/cpibia/tripwatch/compare/v0.1.26...v0.1.27
[0.1.26]: https://github.com/cpibia/tripwatch/compare/v0.1.25...v0.1.26
[0.1.25]: https://github.com/cpibia/tripwatch/compare/v0.1.24...v0.1.25
[0.1.24]: https://github.com/cpibia/tripwatch/compare/v0.1.23...v0.1.24
[0.1.23]: https://github.com/cpibia/tripwatch/compare/v0.1.22...v0.1.23
[0.1.22]: https://github.com/cpibia/tripwatch/compare/v0.1.21...v0.1.22
[0.1.21]: https://github.com/cpibia/tripwatch/compare/v0.1.20...v0.1.21
[0.1.20]: https://github.com/cpibia/tripwatch/compare/v0.1.19...v0.1.20
[0.1.19]: https://github.com/cpibia/tripwatch/compare/v0.1.18...v0.1.19
[0.1.18]: https://github.com/cpibia/tripwatch/compare/v0.1.17...v0.1.18
[0.1.17]: https://github.com/cpibia/tripwatch/compare/v0.1.16...v0.1.17
[0.1.16]: https://github.com/cpibia/tripwatch/compare/v0.1.15...v0.1.16
[0.1.15]: https://github.com/cpibia/tripwatch/compare/v0.1.14...v0.1.15
[0.1.14]: https://github.com/cpibia/tripwatch/compare/v0.1.13...v0.1.14
[0.1.13]: https://github.com/cpibia/tripwatch/compare/v0.1.12...v0.1.13
[0.1.12]: https://github.com/cpibia/tripwatch/compare/v0.1.11...v0.1.12
[0.1.11]: https://github.com/cpibia/tripwatch/compare/v0.1.10...v0.1.11
[0.1.10]: https://github.com/cpibia/tripwatch/compare/v0.1.9...v0.1.10
[0.1.9]: https://github.com/cpibia/tripwatch/compare/v0.1.8...v0.1.9
[0.1.8]: https://github.com/cpibia/tripwatch/compare/v0.1.7...v0.1.8
[0.1.7]: https://github.com/cpibia/tripwatch/compare/v0.1.6...v0.1.7
[0.1.6]: https://github.com/cpibia/tripwatch/compare/v0.1.5...v0.1.6
[0.1.5]: https://github.com/cpibia/tripwatch/compare/v0.1.4...v0.1.5
[0.1.4]: https://github.com/cpibia/tripwatch/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/cpibia/tripwatch/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/cpibia/tripwatch/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/cpibia/tripwatch/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/cpibia/tripwatch/releases/tag/v0.1.0
