# Web Hunter — Report di Test Moduli
> **Target servizio**: `/home/mimmo/Desktop/Pwnzer0tt1Shop` (Flask/Python backend, porta 80)  
> **Engine**: Docker  
> **Immagine**: `ctf-recon-suite:latest`  
> **Data inizio**: 2026-07-10  
> **Autore sezione**: Mimmo (testing singoli moduli)  
> **Collega**: lavora su orchestratore generale e interazione tra moduli (incluso sqlmap/ghauri)

---

## Legenda

| Simbolo | Significato |
|---------|-------------|
| ✅ | Test passato — modulo funziona correttamente |
| ❌ | Test fallito — bug/errore nel modulo |
| ⏳ | In corso |
| ⏭️ | Skippato (non applicabile allo stack del target) |
| 🔲 | Da fare |

---

## Ambiente di test

- **Comando base**: `python3 start.py --path=/home/mimmo/Desktop/Pwnzer0tt1Shop --module=<MOD> --no-target --verbose --dev`
- **`--dev`**: monta `modules/` e `orchestrator/` locali → usare sempre per applicare fix senza rebuild
- **`--no-target`**: salta il prompt interattivo del servizio target
- **Report output**: `Web_Hunter/reports/Pwnzer0tt1Shop/`

### Settings correnti
- `engine`: `docker`
- `target_url`: `http://127.0.0.1:80`
- `timeout_seconds`: `60` (alzato da 15 per sqlmap)

---

## Stack rilevato (Pwnzer0tt1Shop) — `detected_stack.json`

| Flag | Valore | Moduli attivati |
|------|--------|-----------------|
| language | `python` | — |
| framework | `flask` | — |
| has_php | `false` | → phpggc, symfony SKIP |
| has_symfony_twig | `false` | → symfony SKIP |
| has_grpc | `false` | → grpcurl SKIP |
| has_file_upload | `false` | → slipit, exiftool, polyglot SKIP |
| **has_sql_queries** | **`true`** | → sqlmap, ghauri (collega) |
| **has_nosql** | **`true`** | → nosqli SKIP (ha_sql=true blocca trigger) |
| uses_jwt | `false` | → jwt_tool SKIP |
| has_eval_on_input | `false` | → fickling SKIP |
| **db_present_in_domain** | **`true`** | → trufflehog, gitleaks |
| has_outbound_request_on_input | `false` | → ssrf_generic SKIP |
| has_graphql_endpoint | `false` | → graphql_generic SKIP |
| has_xpath_parser | `false` | → xpath_generic SKIP |
| has_file_path_from_input | `false` | → directory_traversal SKIP |
| has_ldap_query | `false` | → ldap_generic SKIP |

**12 endpoint trovati** — candidati SQLi principali: `POST /api/login` (f-string SQLi confermata a livello sorgente), `POST /api/donate`, `POST /api/sell`

---

## TODO List — Pwnzer0tt1Shop

### FASE 0 — Setup e Bootstrap
- ✅ **[SETUP-1]** Build immagine Docker
- ✅ **[SETUP-2]** Pwnzer0tt1Shop up su porta 80
- ✅ **[SETUP-3]** `target_url` impostato
- ✅ **[MODULE-mapping]** 12 endpoint trovati — `endpoints_map.json` OK
- ✅ **[MODULE-stack_detector]** `detected_stack.json` OK

### FASE 1 — Discovery
- ✅ **[MODULE-semgrep]** 9 findings (vedi tabella sotto)
- ✅ **[MODULE-ripgrep]** 1 finding (vedi tabella sotto)
- ✅ **[MODULE-jsluice]** 55 findings (URL/endpoint dal frontend TS)
- ✅ **[MODULE-trufflehog]** 0 findings — nessun segreto trovato
- ✅ **[MODULE-gitleaks]** 0 findings — nessun segreto in git history
- ✅ **[MODULE-nuclei]** 10 findings (vedi tabella sotto)

### FASE 2 — Injection
- ⏭️ **[MODULE-sqlmap]** ci lavora il collega
- ⏭️ **[MODULE-ghauri]** ci lavora il collega
- ✅ **[MODULE-sstimap]** 0 findings
- ✅ **[MODULE-commix]** 0 findings
- ⏭️ **[MODULE-nosqli]** trigger non soddisfatto (has_sql=true blocca)
- ⏭️ **[MODULE-ssrf/graphql/xpath/traversal/ldap]** trigger non soddisfatti

### FASE 3 — Auth
- ⏭️ **[MODULE-jwt_tool]** uses_jwt=false

### FASE 4 — Lang-specific
- ⏭️ **[MODULE-fickling]** has_eval_on_input=false
- ⏭️ **[MODULE-phpggc]** has_php=false
- ⏭️ **[MODULE-symfony]** has_symfony_twig=false
- ✅ **[MODULE-nodejsscan]** skippato correttamente (language=python, non javascript)

### FASE 5 — Upload
- ⏭️ **[MODULE-slipit/exiftool/polyglot]** has_file_upload=false

### FASE 6 — gRPC & XXE
- ⏭️ **[MODULE-grpcurl]** has_grpc=false
- ⏭️ **[MODULE-xxeexploiter]** skippato (no XML-consuming endpoints or XML parsers detected)

---

## Anomalie e bug riscontrati

| # | Modulo | Descrizione bug | File | Stato fix |
|---|--------|----------------|------|-----------|
| 1 | `mapping`, `stack_detector` | `run()` mancava `**kwargs` → `TypeError` in single-module mode | `modules/mapping/endpoint_parser.py:521`, `orchestrator/stack_detector.py:405` | ✅ Fixato 2026-07-10 |

---

## Findings sul target Pwnzer0tt1Shop

### semgrep (9 findings)

| Confidence | Tipo | File:Riga | Dettaglio |
|-----------|------|-----------|-----------|
| high | injection | backend/app.py:111 | `tainted-sql-string` — f-string SQLi: `WHERE username = '{username}'` |
| high | sql | backend/app.py:111 | `sqlalchemy-execute-raw-query` — query raw su connessione diretta |
| high | injection | backend/app.py:111 | `django-sql-injection-cursor-execute` — match cross-rule |
| high | injection | backend/app.py:145 | `nan-injection` — input utente va in contesto numerico |
| medium | injection | backend/app.py:103 | `sql-injection-using-db-cursor-execute` |
| medium | sql | backend/app.py:111 | `formatted-sql-query` — query con formato stringa |
| high | semgrep | Dockerfile:20 | `missing-user` — container gira come root |
| medium | semgrep | backend/app.py:272 | `app-run-param-config` — host=0.0.0.0 in app.run() |
| medium | semgrep | backend/app.py:272 | `debug-enabled` — Flask debug=True in produzione |

### ripgrep (1 finding)

| Confidence | Tipo | File:Riga | Dettaglio |
|-----------|------|-----------|-----------|
| low | path_traversal | backend/app.py:229 | `send_file('./db-data/log.txt')` — path hardcoded, da verificare |

### jsluice (55 findings)
- URL/endpoint dal frontend TypeScript — principalmente riferimenti a `/api/*`
- Nessun segreto hardcoded trovato (0 `secret` type)
- Dettaglio completo in `reports/Pwnzer0tt1Shop/jsluice.json`

### trufflehog / gitleaks
- 0 findings — nessun segreto/credenziale nei file o nella git history

### nuclei (10 findings)
- Trovate 10 vulnerabilità di tipo Low/Info (tutte relative a `http-missing-security-headers` su http://127.0.0.1:80).

### sstimap / commix / xxeexploiter
- **sstimap**: 0 findings.
- **commix**: 0 findings.
- **xxeexploiter**: Skippato (nessun parser XML o endpoint XML-consuming rilevato nel codice).
