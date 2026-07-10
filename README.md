```
▗▖ ▗▖▗▄▄▄▖▗▄▄▖     ▗▖ ▗▖▗▖ ▗▖▗▖  ▗▖▗▄▄▄▖▗▄▄▄▖▗▄▄▖
▐▌ ▐▌▐▌   ▐▌ ▐▌    ▐▌ ▐▌▐▌ ▐▌▐▛▚▖▐▌  █  ▐▌   ▐▌ ▐▌
▐▌ ▐▌▐▛▀▀▘▐▛▀▚▖    ▐▛▀▜▌▐▌ ▐▌▐▌ ▝▜▌  █  ▐▛▀▀▘▐▛▀▚▖
▐▙█▟▌▐▙▄▄▖▐▙▄▞▘    ▐▌ ▐▌▝▚▄▞▘▐▌  ▐▌  █  ▐▙▄▄▖▐▌ ▐▌
```

# Web Hunter — CTF A/D Recon Suite

Suite di ricognizione e sviluppo exploit **whitebox** per competizioni **Attack/Defense**
(CyberChallenge.IT). Dato il sorgente di un servizio bersaglio, Web Hunter lo analizza
in un container Kali isolato ed emette un report strutturato che indica **dove** sono le
vulnerabilità (file:riga, endpoint, parametro) e **con quale tool** confermarle/sfruttarle.

**Filosofia:** in A/D whitebox la recon "vera" è leggere il codice. Web Hunter automatizza
la lettura — mapping degli endpoint, detection dello stack, SAST, secret scanning — e
*orchestra* i tool giusti (sqlmap, SSTImap, jwt_tool, phpggc, grpcurl…) solo dove servono,
senza rumore. Progettato per girare **offline**: i tool sono installati una volta nell'immagine.

> ⚠️ Uso previsto: solo su servizi **di cui hai i sorgenti e l'autorizzazione** (il tuo
> vulnbox in gara, laboratori, CTF). Vedi le regole d'ingaggio in [`DOCS/ARSENAL.md`](DOCS/ARSENAL.md).

---

## Architettura

```
HOST                                    CONTAINER DI ANALISI (Kali + tutti i tool)
┌────────────────────────┐              ┌──────────────────────────────────────────┐
│ start.py               │  docker run  │ /service   ← sorgente target (mount ro)   │
│  • avvia il target     │─────────────▶│ /reports/<svc> ← output (mount rw)        │
│  • builda l'immagine   │              │ /app       ← suite (orchestrator+modules) │
│  • lancia il container │              │   └─ python3 -m orchestrator.run_pipeline │
└────────────────────────┘              └──────────────────────────────────────────┘
```

`start.py` gira sull'**host** e pilota docker/podman. Non c'è Docker-in-Docker: il container
di analisi condivide la rete host (`--network host`), quindi raggiunge il servizio target su
`localhost`. Il codice della suite è **baked** nell'immagine al build; per iterare senza
rebuild si usa `--dev` (monta `modules/` e `orchestrator/` locali nel container).

### Pipeline (`orchestrator/core.py`)

| Fase | Cosa fa | Moduli |
|---|---|---|
| **1 — Bootstrap** | Mapping endpoint + detection stack (sequenziale: producono i contratti dati) | `endpoint_parser`, `stack_detector` |
| **1.5 — Auth** | Login con credenziali stock → salva `auth_state.json` per i tool dinamici | `session_probe` |
| **2 — Analisi** | Esegue in parallelo solo i moduli attivati dai trigger sullo stack | tutti i runner gated |
| **3 — Report** | Aggrega i JSON in report leggibili | `markdown_report`, `stats_tracker`, `quick_report` |

Il **gating** è dichiarativo e centralizzato in `orchestrator/trigger_rules.py`: ogni modulo
si attiva solo se il suo predicato sullo `detected_stack.json` è vero (es. `phpggc` solo se
`has_php`). La concorrenza (semaforo + mutex per gruppo, es. sqlmap/ghauri non insieme) è in
`orchestrator/job_queue.py`.

---

## Struttura del progetto

```
Web_Hunter/
├── start.py                     # entrypoint host — build/run container, avvio target
├── settings.json                # configurazione (engine, timeout, target_url, test_user…)
├── Dockerfile                   # immagine Kali con tutti i tool preinstallati
├── docker-entrypoint.sh         # lancia la pipeline dentro il container
├── orchestrator/
│   ├── core.py                  # loop pipeline + registry moduli
│   ├── run_pipeline.py          # __main__ del container
│   ├── trigger_rules.py         # tabella dichiarativa di attivazione moduli
│   ├── stack_detector.py        # detection linguaggio/framework/sink → detected_stack.json
│   ├── job_queue.py             # concorrenza (semaforo + mutex groups + rate limit)
│   └── colors.py                # output colorato
├── modules/
│   ├── base_runner.py           # classe base: subprocess, timeout, scrittura report
│   ├── mapping/                 # endpoint_parser → endpoints_map.json
│   ├── discovery/               # semgrep, ripgrep, jsluice, trufflehog, gitleaks, nuclei
│   ├── auth/                    # session_probe, jwt_tool
│   ├── injection/               # sqlmap, ghauri, sstimap, commix, nosqli, dalfox, generic
│   ├── lang_specific/           # phpggc, symfony, fickling, nodejsscan, proxy_config, smuggler
│   ├── grpc/                    # grpcurl
│   ├── xxe/                     # xxeexploiter
│   ├── upload/                  # slipit, exiftool, polyglot
│   ├── payload_library/         # loader + selector (PayloadsAllTheThings)
│   ├── reporting/               # markdown_report, quick_report, stats_tracker
│   ├── sync/                    # git_sync (condivisione report tra team)
│   └── webhook/                 # callback_listener (OOB)
├── schemas/                     # JSON schema dei contratti (stack, endpoints, report)
├── tests/                       # unit + integration (pytest) + fixtures
├── reports/<service>/           # output per servizio (git-tracciato per condivisione)
└── DOCS/                        # ARSENAL.md, report di test, questo review
```

---

## I moduli in breve

I moduli **non** fanno discovery propria: leggono i contratti (`detected_stack.json`,
`endpoints_map.json`) e scrivono `json_reports/<modulo>.json` con la stessa struttura.

### Core / mapping
| Modulo | Cosa fa |
|---|---|
| `endpoint_parser` | Estrae route, metodo, file:riga, handler e **parametri** (query/body, encoding JSON) da Flask/FastAPI/Express → `endpoints_map.json` |
| `stack_detector` | Rileva linguaggio, framework e i sink pericolosi (SQL, NoSQL, JWT, eval, SSRF, upload, XXE, XPath, LDAP, path traversal, proxy) → `detected_stack.json` |
| `session_probe` | Trova login/registrazione, si autentica con `test_user` e salva cookie/token in `auth_state.json` |

### Discovery (statica, sempre attiva)
| Modulo | Cosa fa |
|---|---|
| `semgrep` | SAST multi-linguaggio: trova i punti dove l'input finisce in un sink |
| `ripgrep` | Grep mirato su pattern pericolosi (query concatenate, `child_process`, `pickle`, secret…) |
| `jsluice` | Estrae URL/endpoint e segreti dai bundle JS |
| `trufflehog` / `gitleaks` | Secret scanning su file e cronologia git (chiavi JWT, credenziali DB) |
| `nuclei` | Scanner dinamico di misconfig/esposizioni *(local-only)* |

### Injection
| Modulo | Trigger | Cosa fa |
|---|---|---|
| `sqlmap` / `ghauri` | endpoint parametrizzati | Conferma SQLi sull'endpoint; body JSON se rilevato; usa l'auth di `session_probe` |
| `sstimap` | payload library | Conferma SSTI (Jinja2/Twig/EJS) |
| `commix` | payload library | Command injection |
| `nosqli` | `has_nosql` e non SQL | Injection MongoDB (`$ne`, `$gt`…) |
| `dalfox` | endpoint parametrizzati | Fuzzer XSS, output JSON strutturato |
| `*_generic` | sink nel detected_stack | SSRF, GraphQL, XPath, Directory Traversal, LDAP via payload library |

### Auth / lang-specific / altro
| Modulo | Trigger | Cosa fa |
|---|---|---|
| `jwt_tool` | JWT + verifica debole | Attacchi JWT (alg:none, key confusion, cracking HS offline) |
| `phpggc` | `has_php` | Genera gadget chain PHP per deserializzazione |
| `symfony` | Symfony/Twig | Exploit specifici Symfony (secret-fragment RCE) |
| `fickling` | Python + eval su input | Analisi/creazione pickle malevoli |
| `nodejsscan` | JavaScript | SAST Node (deserializzazione, `eval`) |
| `proxy_config` | file `.conf` | Misconfig proxy (alias traversal, esposizione `.git`/`.env`) |
| `smuggler` | file `.conf` | HTTP Request Smuggling / desync *(richiede target attivo)* |
| `grpcurl` | `.proto` presenti | Enumera/chiama metodi gRPC |
| `xxeexploiter` | sempre | Payload XXE |
| `slipit` / `exiftool` / `polyglot` | `has_file_upload` | Bypass upload (zip/tar-slip, EXIF, polyglot) |

---

## Requisiti

- **Host:** Linux, Python 3.10+, `docker` **oppure** `podman`.
- **Build (una volta, con internet):** l'immagine scarica tutti i tool (~qualche GB, SecLists incluso).
- In gara/offline non serve rete: i tool sono già nell'immagine.

---

## Installazione

```bash
git clone <repo> Web_Hunter && cd Web_Hunter

# Scegli l'engine in settings.json ("docker" o "podman"); default: docker
# Build dell'immagine (avviene anche al primo run):
docker build -t ctf-recon-suite:latest .
```

---

## Uso

`start.py` è l'unico entrypoint. Va lanciato **dalla root del progetto**.

```bash
# Interattivo: selezione guidata del path (fzf/TAB), avvio target, analisi completa
./start.py

# Non-interattivo su un sorgente dato
./start.py --path=/percorso/al/servizio

# Solo un modulo (utile per iterare / testare)
./start.py --path=/percorso/al/servizio --module=sqlmap

# Iterare sul codice della suite senza rebuild dell'immagine
./start.py --path=/percorso/al/servizio --dev

# Analisi statica pura, senza avviare il servizio target
./start.py --path=/percorso/al/servizio --no-target
```

### Flag

| Flag | Effetto |
|---|---|
| `--path=PATH` | Path del sorgente (altrimenti selezione interattiva) |
| `--module=NAME` | Esegue solo quel modulo |
| `--no-target` | Salta l'avvio interattivo del servizio target (solo analisi statica) |
| `--dev` | Monta `modules/` e `orchestrator/` locali nel container (no rebuild) |
| `--rebuild` | Clean + build `--no-cache`, poi avvia |
| `--clean` | Rimuove container e immagine `ctf-recon-*`, prune dei layer dangling |
| `--verbose` | Mostra stdout/stderr di tutti i tool |
| `--debug` | Dump compatto delle variabili chiave a ogni step |

I messaggi di stato colorati (`→ ✓ ⚠ ✗`) sono sempre visibili.

### Configurazione — `settings.json`

| Campo | Default | Note |
|---|---|---|
| `engine` | `docker` | `docker` o `podman` |
| `timeout_seconds` | `60` | Timeout per-tool (i runner lo moltiplicano per i tool lenti) |
| `target_url` | — | URL del servizio in esecuzione; impostato in automatico all'avvio del target |
| `max_workers` | `4` | Parallelismo della Fase 2 |
| `rate_limit_rps` | `null` | Token-bucket globale opzionale (disattivo di default) |
| `test_user` | preset | Credenziali usate da `session_probe` per autenticarsi |
| `payload_library_path` | `/assets/…` | PayloadsAllTheThings usato dai runner generic |

---

## Esempio d'uso con risultati

Analisi statica di un micro-servizio Flask vulnerabile (`tests/fixtures/flask_sqli`):

```bash
./start.py --path=tests/fixtures/flask_sqli --no-target
```

**Stack rilevato** (`json_reports/detected_stack.json`, estratto):

```json
{
  "language": "python", "framework": "flask",
  "has_sql_queries": true, "sql_query_locations": [{"file": "app.py", "line": 16}],
  "uses_jwt": true,
  "jwt_verification_locations": [{"file": "app.py", "line": 27, "looks_weak": true, "weak_reason": "verify_disabled"}]
}
```

**Endpoint mappati** (`json_reports/endpoints_map.json`, estratto): il parser riconosce
anche i parametri nel body e l'encoding JSON — informazione che sqlmap/ghauri usano per
costruire la richiesta corretta.

```json
[
  { "path": "/api/login", "method": "POST", "file": "app.py", "line": 9,
    "params": [ {"name": "username", "location": "body", "encoding": "json"},
                {"name": "password", "location": "body", "encoding": "json"} ] },
  { "path": "/api/profile", "method": "GET", "file": "app.py", "line": 23, "params": [] }
]
```

**Report** (`extended_report.md`) — tabella stack + mapping + sezioni per-modulo:

```markdown
# flask_sqli
**Language:** python  **Framework:** flask

| Caratteristica | Rilevato |
|---|---|
| Query SQL | **Sì** |
| JWT       | **Sì** |

## Mapping
| Path          | Metodo | File:Riga   | Auth |
| `/api/login`  | POST   | `app.py:9`  | —    |
| `/api/profile`| GET    | `app.py:23` | —    |
```

In un ambiente con i tool installati (l'immagine Docker), la Fase 2 aggiunge le sezioni
`Injection — SQL (sqlmap)`, `Auth — JWT`, ecc. con i finding confermati (parametro, tecnica,
confidence). Qui sull'host senza i tool i moduli dinamici terminano con un errore pulito
("tool not found in PATH") e non compaiono nel report.

### Output prodotto

```
reports/<service>/
├── extended_report.md      # report completo, sezioni per fase/modulo
├── quick_report.md         # sintesi: tabella stack + sole vulnerabilità HIGH
├── stats.json              # conteggio finding HIGH per tipo canonico
└── json_reports/
    ├── detected_stack.json # contratto: stack + sink (file:riga)
    ├── endpoints_map.json  # contratto: endpoint + parametri
    ├── auth_state.json     # cookie/token da session_probe
    └── <modulo>.json       # un report per modulo eseguito
```

---

## Test

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install pytest
pytest tests/ -v
```

I test coprono `stack_detector`, `endpoint_parser`, `trigger_rules` (unit) e la pipeline
(integration). Alcuni test risultano disallineati rispetto a scelte di design recenti e a
un paio di bug minori: dettaglio ed elenco puntuale in
[`DOCS/REVIEW_2026-07-10.md`](DOCS/REVIEW_2026-07-10.md).
