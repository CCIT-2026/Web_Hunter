# Web Hunter — CTF A/D Recon Suite

## Cos'è

Tool di recon automatizzata per competizioni CTF Attack/Defence. Analizza il sorgente di un servizio target, rileva lo stack tecnologico, mappa gli endpoint, e lancia in parallelo una batteria di tool di sicurezza (semgrep, sqlmap, ghauri, nuclei, ecc.). Produce due report: uno esteso e uno rapido focalizzato sulle vulnerabilità HIGH.

Gira come container Docker/Podman. L'utente interagisce via `start.py` sull'**host** — è lui che builda il container e monta il sorgente del servizio in bind-mount.

---

## Architettura

```
HOST
└── start.py              ← entrypoint interattivo (fzf picker, avvio servizio target, build immagine)
    └── docker run ctf-recon-suite
        └── orchestrator/run_pipeline.py   ← __main__ del container
            └── orchestrator/core.py       ← pipeline orchestrator
                ├── Phase 1: mapping + stack_detector  (sequenziali)
                ├── Phase 1.5: session_probe            (sequenziale)
                └── Phase 2: tutti i moduli in parallelo via JobQueue
                    └── Phase 3: markdown_report + stats_tracker + quick_report
```

### Moduli principali

| Area | Moduli |
|------|--------|
| Mapping | `endpoint_parser` — estrae endpoint da sorgente |
| Stack | `stack_detector` — rileva linguaggio, framework, feature (SQL, JWT, upload, ecc.) |
| Discovery | `semgrep`, `ripgrep`, `jsluice`, `nuclei`, `trufflehog`, `gitleaks` |
| Injection | `sqlmap`, `ghauri`, `sstimap`, `commix`, `nosqli`, `dalfox` |
| Auth | `session_probe`, `jwt_tool` |
| Lang-specific | `phpggc`, `symfony`, `fickling`, `nodejsscan` |
| Upload | `slipit`, `exiftool`, `polyglot` |
| XXE | `xxeexploiter` |
| gRPC | `grpcurl` |
| Generic/payload | `ssrf_generic`, `graphql_generic`, `xpath_generic`, `directory_traversal`, `ldap_generic` |
| Reporting | `markdown_report`, `stats_tracker`, `quick_report` |

---

## File chiave

```
/app/output/                         ← tutto il codice modificabile (Claudio env)
├── start.py                         ← CLI host-side (TUI, fzf, avvio servizio)
├── settings.json                    ← configurazione (engine, target_url, timeout, ecc.)
├── Dockerfile
├── orchestrator/
│   ├── core.py                      ← pipeline orchestrator + MODULE_REGISTRY
│   ├── run_pipeline.py              ← __main__ container
│   ├── job_queue.py                 ← ThreadPoolExecutor con mutex groups
│   ├── trigger_rules.py             ← TRIGGERS: quali moduli girano in base allo stack
│   ├── stack_detector.py            ← rileva stack da sorgente
│   └── colors.py                    ← stampe colorate condivise (dentro container)
├── modules/
│   ├── base_runner.py               ← BaseRunner: sh(), add_finding(), tool_available()
│   ├── mapping/endpoint_parser.py
│   ├── auth/session_probe.py        ← registra/logga utente test, scrive auth_state.json
│   ├── discovery/semgrep_runner.py
│   ├── injection/sqlmap_runner.py
│   ├── injection/ghauri_runner.py   ← parser stderr, filtro false-positive
│   ├── reporting/markdown_report.py ← extended_report.md (tutto)
│   ├── reporting/stats_tracker.py   ← stats.json (conteggi HIGH per tipo)
│   ├── reporting/quick_report.py    ← quick_report.md (solo HIGH, barchart)
│   └── sync/git_sync.py             ← init/commit/clone/pull (sharing colleghi, TODO daemon)
├── assets/
│   ├── .logo/ascii_art.txt          ← logo ASCII "WEB HUNTER"
│   └── payloads_all_the_things.json ← payload library (SSRF, GraphQL, XPath, ecc.)
└── DOCS/
    ├── PROGETTO.md                  ← questo file
    ├── TODO.md                      ← feature da completare (git daemon, interactsh, PATT)
    └── ARSENAL.md                   ← tool disponibili nel container
```

---

## Output di ogni analisi

```
reports/ServiceName/
├── quick_report.md          ← PRIMO DA APRIRE: solo HIGH, barchart, stack table
├── extended_report.md       ← report completo con tutto
├── json_reports/
│   ├── detected_stack.json  ← stack rilevato (linguaggio, framework, feature boolean)
│   ├── endpoints_map.json   ← lista endpoint (path, method, file:riga, auth)
│   ├── auth_state.json      ← stato autenticazione (cookie/token sessione)
│   ├── stats.json           ← conteggi HIGH per tipo vuln
│   ├── semgrep_raw.json     ← raw output semgrep (debug)
│   └── *.json               ← un file per ogni modulo eseguito
└── raw_datas/
    ├── sqlmap_*.txt         ← stdout/stderr sqlmap per endpoint
    └── ghauri_*.txt         ← stdout/stderr ghauri per endpoint
```

---

## Come si usa

```bash
# Analisi interattiva (fzf picker per il path)
./start.py

# Analisi diretta su un servizio
./start.py --path=/srv/targets/Pwnzer0tt1Shop

# Sviluppo: monta modules/ e orchestrator/ senza rebuild
./start.py --path=/srv/targets/Pwnzer0tt1Shop --dev

# Singolo modulo
./start.py --path=/srv/targets/Pwnzer0tt1Shop --module=sqlmap

# Rebuild immagine da zero
./start.py --rebuild

# Pulizia container e immagine (NON tocca distrobox o altri progetti)
./start.py --clean
```

`settings.json` contiene: `engine` (docker/podman), `target_url`, `timeout_seconds`, `max_workers`, `test_user` (credenziali per session_probe), `payload_library_path`.

---

## Convenzioni codice

- **Findings**: `{"type": "sqli", "confidence": "high|medium|low", "file": "...", "line": N, "endpoint": "...", "method": "GET", "detail": "...", "unlikely_path": bool, "requires_manual_review": bool}`
- **Pipeline contracts**: `detected_stack.json` e `endpoints_map.json` in `json_reports/` — tutti i moduli li leggono
- **Colori**: usare `orchestrator.colors` dentro il container, `_C` in `start.py` sull'host
- **Claudio env**: modifiche → `/app/output/`, riferimento → `/app/context/` (read-only)

---

## TODO principali

1. **Git sharing** (`DOCS/TODO.md`): condivisione report via `git daemon` su `git://ip/Service`. Bloccato da `git-daemon` non disponibile su Bluefin senza reboot. Codice scritto e documentato, pronto da reintegrare.
2. **Interactsh OOB**: rilevamento blind vulns (SSRF, XXE blind, blind SQLi/CMDI) via server out-of-band custom. Da implementare: generazione URL unico, iniezione nei payload, poll post-analisi.
3. **Payload All The Things fuzzer**: `fuzzer_runner` dedicato che usa `payloads_all_the_things.json` per categorie non coperte da tool dedicati (header injection, prototype pollution, ecc.).
