# Prompt per Claude Code — CTF A/D Whitebox Recon & Analysis Suite

## Contesto
Sei un Senior Security Engineer e giocatore veterano di CTF Attack & Defense (stile CyberChallenge.IT).
Devi costruire una **suite containerizzata di analisi whitebox** da usare durante la fase di preparazione di una gara A/D, sulla mia macchina locale, contro copie locali dei servizi avversari.

**Vincoli di gara che il tool deve rispettare per design:**
- Vietato lanciare scanner/fuzzer automatici o generare traffico massivo contro l'infrastruttura reale di gara. Questo tool gira **solo contro copie locali** dei servizi, mai contro target di gara.
- "No AI / Offline": nessuna chiamata a LLM o API esterne durante l'esecuzione dei tool. Tutto locale.
- L'obiettivo finale non è "auto-exploit": ogni finding va riportato con **file + riga esatta** nel sorgente, perché le vulnerabilità logiche vanno verificate a mano da me. Il tool fa ricognizione e mapping, non decide da solo cosa sfruttare.
- Il rate-limit basso vale **solo per la gara reale**, non per i test locali: qui non c'è nessuna infrastruttura da proteggere. Il rate-limit resta comunque disponibile come opzione **disattivabile** in `settings.json`, utile solo per evitare che più tool in parallelo (es. sqlmap + ghauri + commix insieme) saturino/crashino il servizio locale durante test pesanti — è una precauzione di stabilità, non di compliance. Default: nessun limite in locale.

## Obiettivo
Un **Container di Controllo** (buildabile con Docker o Podman) che, dato il path di un servizio (codice sorgente whitebox), esegue una pipeline di ricognizione modulare e intelligente, e produce report JSON standardizzati, cross-referenziabili tra i moduli.

---

## 1. Architettura generale

Struttura a moduli indipendenti + un orchestratore centrale. Un file per micro-area, nessun mega-script monolitico.

```
/project-root
├── start.py                  # entrypoint CLI (interattivo o a flag)
├── settings.json             # webhook url, rate-limit, timeout, ecc. (editabile post-run)
├── aliases.txt               # alias/funzioni da appendere a ~/.bashrc
├── Dockerfile
├── Dockerfile.podman (se necessario differenziare)
├── docker-compose.yml (opzionale, per multi-service)
├── orchestrator/
│   ├── core.py                # loop principale, scheduling, lock/semafori
│   ├── stack_detector.py      # analizza il sorgente e produce detected_stack.json
│   ├── trigger_rules.py       # tabella trigger -> modulo (dichiarativa)
│   └── job_queue.py           # gestione concorrenza custom
├── modules/
│   ├── mapping/
│   │   └── endpoint_parser.py  # produce endpoints_map.json + detected_stack.json
│   ├── discovery/
│   │   ├── jsluice_runner.py
│   │   ├── semgrep_runner.py
│   │   ├── ripgrep_runner.py   # legge wordlist da .txt
│   │   ├── trufflehog_runner.py
│   │   ├── gitleaks_runner.py
│   │   └── nuclei_runner.py
│   ├── injection/
│   │   ├── sqlmap_runner.py
│   │   ├── ghauri_runner.py
│   │   ├── sstimap_runner.py
│   │   ├── commix_runner.py
│   │   └── nosqli_runner.py
│   ├── auth/
│   │   └── jwt_tool_runner.py
│   ├── lang_specific/
│   │   ├── phpggc_runner.py       # solo se PHP rilevato
│   │   ├── symfony_runner.py      # solo se Symfony/Twig rilevato
│   │   ├── fickling_runner.py     # solo se Python + eval/pickle su input arbitrario
│   │   └── nodejsscan_runner.py   # solo se Node.js rilevato
│   ├── xxe/
│   │   └── xxeexploiter_runner.py
│   ├── upload/
│   │   ├── slipit_runner.py       # solo se upload endpoint rilevato
│   │   ├── exiftool_runner.py     # solo se upload + file eseguibili
│   │   └── polyglot_runner.py
│   ├── grpc/
│   │   └── grpcurl_runner.py      # auto-discovery .proto + bridge verso gli altri moduli
│   ├── payload_library/
│   │   ├── loader.py               # carica e indicizza payloads_all_the_things.json
│   │   └── selector.py             # selezione filtrata per categoria/contesto, cap sui tentativi
│   ├── reporting/
│   │   └── markdown_report.py      # aggrega tutti i report JSON in reports/<service>/report.md
│   ├── sync/
│   │   └── git_sync.py             # init repo locale, clone/pull da collega via VPN
│   └── webhook/
│       └── callback_listener.py   # emula interactsh: riceve ping su webhook URL
├── assets/
│   └── payloads_all_the_things.json   # copiato nell'immagine in fase di build
├── schemas/                    # JSON schema condivisi tra i moduli
├── reports/                    # BIND MOUNT verso l'host: output per servizio, per modulo + report.md finale
└── tests/
    ├── unit/                   # test dei singoli runner
    ├── integration/            # test del coordinamento tra moduli
    └── fixtures/                # micro-servizi di esempio (PHP, Flask, Node, gRPC)
```

---

## 2. Modulo Mapping (fondamentale, gira sempre per primo)

Analizza il sorgente e produce **due artefatti**:

1. `endpoints_map.json` — per ogni endpoint: path, metodo HTTP, file sorgente, riga di implementazione, eventuali parametri, middleware/decoratori di auth rilevati.
2. `detected_stack.json` — flag booleani/enum derivati dal codice, che guidano tutta l'attivazione condizionale a valle: `language`, `framework`, `has_php`, `has_symfony_twig`, `has_grpc` (+ path dei `.proto` trovati), `has_file_upload` (+ file:riga delle funzioni di upload), `has_sql_queries` (+ file:riga), `has_nosql`, `uses_jwt` (+ file:riga della verifica), `has_eval_on_input` (Python), `db_present_in_domain` (bool — usato per gating di trufflehog/gitleaks).

Questo secondo file è il contratto che l'orchestratore usa per decidere quali moduli lanciare. Nessun altro modulo deve reimplementare la propria detection dello stack: la leggono da qui.

---

## 2bis. Schemi JSON dei contratti dati principali

Questi due schemi sono il contratto fisso su cui si basa tutta l'attivazione condizionale a valle (sezione 3) e la payload library (sezione 4bis). Claude Code deve partire da qui, non inventarli al primo step.

### `endpoints_map.json`

```json
[
  {
    "path": "/api/login",
    "method": "POST",
    "file": "app/routes/login.py",
    "line": 42,
    "handler_function": "login_handler",
    "params": [
      { "name": "username", "location": "body", "type": "string" },
      { "name": "password", "location": "body", "type": "string" }
    ],
    "auth": {
      "required": true,
      "type": "jwt",
      "file": "app/middleware/auth.py",
      "line": 17
    }
  }
]
```

- `auth` è `null` se l'endpoint non ha protezione rilevata.
- `params` va popolato quando ricavabile staticamente dal codice (query string, body, path param); se non ricavabile, array vuoto — non inventare parametri.
- Un endpoint può comparire più volte se ha handler diversi per metodo (una entry per combinazione path+method).

### `detected_stack.json`

```json
{
  "language": "python",
  "framework": "flask",

  "has_php": false,
  "has_symfony_twig": false,

  "has_grpc": false,
  "grpc_proto_files": [],

  "has_file_upload": false,
  "file_upload_locations": [],

  "has_sql_queries": true,
  "sql_query_locations": [
    { "file": "app/routes/login.py", "line": 45, "endpoint": "/api/login" }
  ],

  "has_nosql": false,

  "uses_jwt": true,
  "jwt_verification_locations": [
    {
      "file": "app/middleware/auth.py",
      "line": 17,
      "looks_weak": false,
      "weak_reason": null
    }
  ],

  "has_eval_on_input": false,
  "eval_locations": [],

  "db_present_in_domain": true,

  "has_outbound_request_on_input": false,
  "ssrf_locations": [],

  "has_graphql_endpoint": false,
  "graphql_locations": [],

  "has_xpath_parser": false,
  "xpath_locations": [],

  "has_file_path_from_input": false,
  "path_traversal_locations": [],

  "has_ldap_query": false,
  "ldap_locations": []
}
```

Regole per ogni campo `*_locations`: array di oggetti `{ "file": ..., "line": ..., ...campi specifici della categoria }`, mai stringhe libere — devono restare parsabili dagli altri moduli (es. `payload_library/selector.py` li usa per decidere su quale endpoint tentare un payload).

`looks_weak` in `jwt_verification_locations` è il campo che decide se `jwt_tool` fa test attivi o skippa (vedi sezione 3).

Ogni nuovo flag booleano aggiunto in futuro a `detected_stack.json` deve avere il suo array `*_locations` gemello con lo stesso pattern, per restare coerente con tutto il resto della pipeline.

---

## 3. Regole di attivazione condizionale (trigger_rules.py)

Dichiarale come tabella dati (non if/else sparsi nei runner), tipo:

```python
TRIGGERS = {
    "phpggc":        lambda stack: stack["has_php"],
    "symfony":       lambda stack: stack["has_symfony_twig"],
    "fickling":      lambda stack: stack["language"] == "python" and stack["has_eval_on_input"],
    "nodejsscan":    lambda stack: stack["language"] == "javascript",
    "grpcurl":       lambda stack: stack["has_grpc"],
    "slipit":        lambda stack: stack["has_file_upload"],
    "exiftool":      lambda stack: stack["has_file_upload"],
    "sqlmap":        lambda stack: stack["has_sql_queries"],
    "ghauri":        lambda stack: stack["has_sql_queries"],
    "nosqli":        lambda stack: stack["has_nosql"] and not stack["has_sql_queries"],
    "jwt_tool":      lambda stack: stack["uses_jwt"] and any(loc["looks_weak"] for loc in stack["jwt_verification_locations"]),
    "trufflehog":    lambda stack: stack["db_present_in_domain"],
    "gitleaks":      lambda stack: stack["db_present_in_domain"],
}
```

`jwt_tool` è un caso speciale: prima verifica (whitebox, via semgrep/lettura mirata) se la verifica firma è debole (alg none, secret hardcoded, verify=False); solo se sì, testa attivamente. Se la funzione è sicura, salta il test e lo dichiara esplicitamente nel report ("skip: verifica JWT robusta, vedi file:riga").

I moduli che non hanno condizioni di gating (es. `mapping`, `semgrep`, `ripgrep`) girano sempre.

Le credenziali trovate da jsluice il cui endpoint associato non risulta in `endpoints_map.json` vanno in una sezione separata del report, es. `unlikely_paths`, non nel corpo principale dei findings.

---

## 4. Formato dati condiviso

Ogni modulo scrive un JSON in `reports/<service>/<modulo>.json` seguendo uno schema comune minimo:

```json
{
  "module": "sqlmap",
  "service": "esempio1",
  "timestamp": "...",
  "status": "completed | skipped | error",
  "skip_reason": "string | null",
  "findings": [
    {
      "type": "sqli",
      "file": "app/routes/login.py",
      "line": 42,
      "endpoint": "/api/login",
      "method": "POST",
      "confidence": "high | medium | low",
      "detail": "...",
      "source_module": "sqlmap"
    }
  ]
}
```

Ogni modulo può leggere gli output degli altri (es. sqlmap legge `mapping/endpoints_map.json` per sapere dove colpire, senza fare discovery propria).

---

## 4bis. Payload Library condivisa (PayloadsAllTheThings)

Ho una copia parsata dell'intero repo PayloadsAllTheThings in `payloads_all_the_things.json`: circa 629 oggetti, ciascuno con `category`, `section`, `subsection`, `language`, `payload`. Copre 61 categorie, incluse alcune per cui **non esiste un tool dedicato** nella lista sopra (SSRF, GraphQL Injection, Directory Traversal, XPath Injection, LDAP Injection, ecc.) e altre dove funge da complemento ai tool dedicati (SQLi, XXE, Command Injection, JWT).

**Ruolo nel sistema**: non è un modulo di "attacco" a sé, è una libreria dati che gli altri moduli interrogano.

- `loader.py` carica il JSON una volta e lo indicizza per `category` (case-insensitive, con mapping alle categorie interne usate da `trigger_rules.py`, es. `"SQL Injection"` → `sqli`, `"Server Side Request Forgery"` → `ssrf`).
- `selector.py` espone una funzione tipo `get_candidates(category, context=None, language=None, max_results=N)` che i runner chiamano per ottenere payload plausibili, filtrati per `language` quando coerente con lo stack rilevato (es. non proporre payload `powershell` se il target è un servizio Linux/bash).
- **Nessun invio massivo**: `max_results` di default basso (configurabile in `settings.json`, es. `payload_library_max_per_endpoint: 3`), e ogni tentativo va giustificato dal mapping (un endpoint/parametro concreto trovato nel sorgente), non sparato "a tappeto" su tutti gli endpoint del servizio.
- Ogni tentativo loggato nel report standard del modulo chiamante con: payload usato, categoria, endpoint/file:riga bersaglio, esito. Se non c'è nessun endpoint plausibile per una categoria (es. GraphQL payload ma nessun endpoint GraphQL nel mapping), quella categoria va skippata con motivazione esplicita, stesso pattern usato altrove per i tool condizionali.

**Copertura categorie senza tool dedicato**: per SSRF, GraphQL Injection, Directory Traversal, XPath Injection, LDAP Injection (e altre categorie presenti nel JSON ma non coperte da un tool automatico nella tua lista), crea un runner leggero (`modules/injection/generic_category_runner.py` o simile) che si attiva solo se il mapping rileva nel sorgente un pattern coerente con quella categoria (es. uso di `requests.get(url_da_input_utente)` per SSRF, parser XML/XPath per XPath Injection), pesca i candidati dalla payload library, e testa in modo mirato (1-2 richieste per endpoint, mai un giro esaustivo su tutti i 34 payload SSRF disponibili).

Aggiorna `trigger_rules.py` per includere queste categorie aggiuntive, coerenti col resto della tabella:

```python
TRIGGERS.update({
    "ssrf_generic":        lambda stack: stack.get("has_outbound_request_on_input", False),
    "graphql_generic":     lambda stack: stack.get("has_graphql_endpoint", False),
    "xpath_generic":       lambda stack: stack.get("has_xpath_parser", False),
    "directory_traversal": lambda stack: stack.get("has_file_path_from_input", False),
    "ldap_generic":        lambda stack: stack.get("has_ldap_query", False),
})
```

`stack_detector.py` va quindi esteso per rilevare anche questi pattern (non solo `has_php`/`has_grpc`/ecc. già previsti), sempre con file:riga della funzione sospetta salvato in `detected_stack.json`.

---

## 5. Orchestratore

- Scheduling parallelo con **lock/semafori custom** (no esecuzioni sequenziali stupide), scritto a mano, non solo `ThreadPoolExecutor` di default senza controllo di concorrenza — voglio controllo esplicito su quanti job girano in parallelo e quali si escludono a vicenda (es. moduli che scrivono sullo stesso file di stato, o più tool che colpiscono lo stesso endpoint contemporaneamente).
- Rate-limit **opzionale**, spento di default, attivabile via `settings.json` (`rate_limit_rps: null` = disattivato). Serve solo a evitare che troppi moduli in parallelo saturino il servizio locale, non è un requisito di policy come in gara.
- Modalità: `run all` (solo i moduli triggerati), oppure singolo modulo su richiesta (`--module=sqlmap`).
- Logging chiaro di cosa è stato skippato e perché (traccia sempre la motivazione, per audit).

---

## 6. CLI

- Solo tre flag globali: `--help`, `--verbose`, `--debug`.
- Interattiva se lanciata senza argomenti (chiede path del servizio).
- Con flag: `./start.py --path=/path/to/service`.
- Un container Docker/Podman per servizio, nominato in modo deterministico dal path (path diversi → container diversi, stesso path → stesso container/aggiornamento).
- Selezione Docker vs Podman via argomento esplicito (es. `--engine=docker|podman`), non autodetect silenzioso.
- Flag aggiuntivi non "globali" ma legati al comando di analisi: `--module=<nome>` per lanciare un singolo modulo (vedi sezione 5), `--clone=<git-url>` per sincronizzarsi con l'analisi di un collega invece di ripartire da zero (vedi sezione 8ter).

---

## 7. Networking e volumi

- **`start.py` gira sull'host**, non dentro il container di controllo. È lui che invoca `docker`/`podman` (a seconda di `--engine`) per buildare/avviare sia il container di analisi sia, se necessario, il container del servizio bersaglio. Non c'è quindi Docker-in-Docker: è un normale process host-side che orchestra container fratelli, non annidati. Motivo del doppio supporto Docker/Podman: il team usa entrambi (io Podman, il mio compagno Docker), non è un compromesso tecnico — deve funzionare in modo identico con `--engine=docker` o `--engine=podman`.
- Rete condivisa con l'host: i servizi lanciati devono essere raggiungibili anche dall'host senza dover pubblicare porte manualmente ogni volta.
- Il sorgente del servizio va montato come volume nel container di analisi; in fase di copia va **escluso `.git`**.
- `reports/` è in **bind mount** con l'host (es. `./reports/<service>` sull'host ↔ `/reports/<service>` nel container), non un volume Docker anonimo: deve essere possibile aprire `report.md` con un editor/browser sull'host mentre il container gira o dopo che ha finito, senza dover fare `docker cp`.
- I comandi Docker/Podman generati da `start.py` devono essere praticamente identici a parità di funzionalità (stessa CLI syntax dove possibile, wrapper unico che astrae le differenze, non due codepath duplicati mantenuti a mano).

---

## 8. settings.json

Generato con valori di default al primo avvio, poi editabile a mano:
```json
{
  "webhook_url": "",
  "rate_limit_rps": null,
  "timeout_seconds": 15,
  "engine": "docker",
  "wordlists_path": "/home/wordlists",
  "payload_library_path": "/assets/payloads_all_the_things.json",
  "payload_library_max_per_endpoint": 3
}
```
`rate_limit_rps: null` = nessun limite (default, uso locale). Un valore numerico lo attiva (utile solo per non saturare il servizio locale durante test paralleli pesanti, oppure — se un giorno vorrai simulare le condizioni di gara — per allenarti con lo stesso limite che avrai lì).

Il webhook_url viene usato dal modulo `callback_listener` per emulare il comportamento di interactsh (ping in ingresso su URL fornito, senza servizio esterno reale).

---

## 8bis. Report finale in Markdown

Oltre ai JSON per modulo, `reporting/markdown_report.py` genera `reports/<service>/report.md`, leggendo tutti i JSON prodotti (`endpoints_map.json`, `detected_stack.json`, e ogni `reports/<service>/<modulo>.json`) e assemblandoli seguendo **l'ordine delle fasi della pipeline**, non l'ordine di scrittura dei file:

```markdown
# <nome servizio>

Breve descrizione (linguaggio, framework, path analizzato, timestamp analisi).

| Caratteristica | Rilevato |
|---|---|
| PHP | Sì/No |
| Symfony/Twig | Sì/No |
| gRPC | Sì/No |
| File upload | Sì/No |
| Query SQL | Sì/No |
| NoSQL | Sì/No |
| JWT | Sì/No |
| eval/pickle su input | Sì/No |
| SSRF | Sì/No |
| GraphQL | Sì/No |
| XPath | Sì/No |
| Path Traversal | Sì/No |
| LDAP | Sì/No |

(tabella generata direttamente dai campi booleani di `detected_stack.json`, una riga per flag)

## Mapping
Tabella endpoint (path, metodo, file:riga, auth) da `endpoints_map.json`.

## Discovery
Findings di jsluice/semgrep/ripgrep/trufflehog/gitleaks/nuclei, con sezione separata "Path improbabili" per le credenziali senza endpoint associato.

## Injection
Findings di sqlmap/ghauri/sstimap/commix/nosqli, raggruppati per endpoint.

## Auth (JWT)
Esito jwt_tool o motivo di skip.

## Moduli specifici per linguaggio/stack
phpggc/symfony/fickling/nodejsscan — solo le sezioni pertinenti allo stack rilevato, il resto omesso (non "N/A" per ogni tool non applicabile).

## Upload & File
slipit/exiftool/polyglot, se pertinenti.

## gRPC
Se pertinente.

## Payload Library (categorie senza tool dedicato)
SSRF/GraphQL/XPath/Directory Traversal/LDAP, con payload usato e esito.

## Findings non verificabili automaticamente
Elenco dei punti segnalati con file:riga che richiedono verifica manuale (vulnerabilità logiche).
```

Regola generale: se un modulo è stato skippato per lo stack rilevato, **non compare nel report** (niente rumore tipo "PHP: N/A" su un servizio Node) — compare solo un cenno nella tabella iniziale se pertinente al flag booleano.

---

## 8ter. Sincronizzazione tra collaboratori (Git locale via VPN)

Scenario: io avvio l'analisi su un servizio, il compagno di squadra vuole partire dai miei risultati invece di rifare tutto da zero, siamo sulla stessa VPN di gara (niente GitHub/servizi esterni).

- Al primo avvio dell'analisi su un servizio, il container inizializza un repo git **senza remote** dentro `reports/<service>/` (che essendo bind mount è già visibile e raggiungibile dall'host, quindi anche da altri host in VPN se la cartella/porta viene esposta).
- Ogni volta che un modulo scrive/aggiorna un report, `git_sync.py` fa un commit incrementale (non un commit gigante a fine analisi) — così anche un'analisi parziale è sincronizzabile.
- All'avvio, se lanciato in modalità interattiva su un servizio senza analisi locale ancora completata, il tool chiede: **"Nuova analisi o sincronizza con analisi esistente?"**. Se sincronizza, chiede l'URL del repo del collega.
- Modalità non interattiva equivalente: `./start.py --path=esempio --clone=git@<ip-collega>:path/to/reports/esempio`.
- Il clone/pull usa il protocollo git standard (ssh o git://) puntato direttamente alla cartella `reports/<service>` del collega, che essendo un repo git valido (anche non bare) è comunque clonabile in VPN — non serve un server git centralizzato né bare repo dedicato per questo scenario a due.
- Se il pull porta modifiche in conflitto con analisi già in corso in locale, il tool si ferma e chiede risoluzione manuale — niente merge automatico di findings di sicurezza.

---

## 9. Dockerfile

- Scarica tutti i tool elencati (jsluice, semgrep, ripgrep, trufflehog, gitleaks, nuclei, sqlmap, ghauri, sstimap, commix, nosqli-scanner equivalente, jwt_tool, phpggc, fickling, nodejsscan, xxeexploiter, grpcurl, exiftool).
- Scarica SecLists (e altre wordlist utili) dentro `/home/wordlists`.
- Copia `assets/payloads_all_the_things.json` dentro l'immagine in `/assets/payloads_all_the_things.json` (path fisso, coerente con `payload_library_path` in `settings.json`).
- Predisponi varianti/argomenti build per Docker e Podman.

---

## 10. aliases.txt

File nella root con alias/funzioni bash pensate per l'uso rapido della suite (es. avvio rapido su un path, tail dei report, reset di un container), da appendere a `~/.bashrc` con uno script di setup dedicato (non farlo silenziosamente dentro il Dockerfile).

---

## 11. Test suite finale

- **Unit test** per ogni runner di modulo, con fixture di micro-servizi finti (uno PHP, uno Flask con eval, uno Node, uno con gRPC/.proto, uno con endpoint di upload) per verificare che il trigger si attivi/disattivi correttamente e che il parsing file:riga sia corretto.
- **Integration test** che verificano che l'orchestratore triggeri solo i moduli attesi dato un `detected_stack.json` di esempio, che il parallelismo rispetti i lock, e che il rate-limit venga rispettato.
- Framework: pytest per la parte Python; script bash per smoke test di build/run dei container (Docker e Podman).

---

## Metodo di lavoro richiesto a Claude Code

1. Proponi prima uno schema JSON definitivo condiviso (`schemas/`) e la tabella `TRIGGERS` completa, prima di scrivere i runner — è il contratto su cui si regge tutta la sinergia tra moduli. **Al termine di questo step, FERMATI esplicitamente e notificalo in modo inequivocabile** (es. "STEP 1 COMPLETATO — in attesa di conferma per proseguire"), senza avviare lo step 2 di tua iniziativa: devo cambiare modello (da Opus a Sonnet) prima di continuare, e sto lavorando in auto mode, quindi se non ti fermi esplicitamente procedi in autonomia senza darmi la possibilità di intervenire.
2. Poi implementa in ordine: mapping → stack_detector → orchestrator core (senza runner, solo scheduling su moduli finti) → discovery runners → injection runners → moduli condizionali (php/symfony/fickling/node/grpc/upload) → payload_library → reporting/markdown_report → sync/git_sync → webhook listener → CLI → Dockerfile → aliases → test suite.
3. Ad ogni step, spiega le scelte architetturali **solo se non ovvie**, in poche righe — non serve un riepilogo prosastico di cosa hai appena scritto, il codice deve parlare da sé.

**Vincolo di budget**: la finestra di token disponibile è limitata (~3h), quindi sii sintetico in ogni risposta intermedia: niente ricapitolazioni di quanto già fatto, niente spiegazioni ridondanti tra uno step e l'altro, va bene procedere e mostrare solo diff/file nuovi. Se un modulo è meccanico e ricalca il pattern di uno già scritto (es. i vari `*_runner.py`), non ripetere la spiegazione della struttura, limitati a evidenziare cosa cambia.
