# Web Hunter — Report di Test Moduli
> **Target servizio**: `/home/mimmo/Desktop/Pwnzer0tt1Shop` (Flask/Python backend, porta 80)  
> **Engine**: Docker  
> **Immagine**: `ctf-recon-suite:latest`  
> **Data inizio**: 2026-07-10  
> **Autore sezione**: Mimmo (testing singoli moduli)  
> **Collega**: lavora su orchestratore generale e interazione tra moduli

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

- **Comando base (modulo singolo)**:
  ```bash
  python3 start.py --path=/home/mimmo/Desktop/Pwnzer0tt1Shop --module=<MODULO> --no-target --verbose --dev
  ```
- **Flag `--dev`**: monta `modules/` e `orchestrator/` locale sull'immagine → usare SEMPRE per applicare fix ai runner senza rebuild.
- **Flag `--no-target`**: salta il prompt interattivo di avvio del servizio target.
- **Report output**: `Web_Hunter/reports/Pwnzer0tt1Shop/`

### Note setup iniziale
- `settings.json`: engine = `docker`, `target_url` = `http://127.0.0.1:80` ✅
- Servizio Pwnzer0tt1Shop: attivo su porta 80 via `docker compose up -d` ✅
- Immagine `ctf-recon-suite:latest`: buildata ✅

---

## Stack rilevato (Pwnzer0tt1Shop) — da `detected_stack.json`

| Flag | Valore | Implicazione |
|------|--------|--------------|
| language | `python` | — |
| framework | `flask` | — |
| has_php | `false` | → phpggc, symfony SKIP |
| has_symfony_twig | `false` | → symfony SKIP |
| has_grpc | `false` | → grpcurl SKIP |
| has_file_upload | `false` | → slipit, exiftool, polyglot SKIP |
| **has_sql_queries** | **`true`** | → **sqlmap, ghauri attivi** |
| **has_nosql** | **`true`** | → nosqli attivo (solo se NOT has_sql) |
| uses_jwt | `false` | → jwt_tool SKIP |
| has_eval_on_input | `false` | → fickling SKIP |
| **db_present_in_domain** | **`true`** | → **trufflehog, gitleaks attivi** |
| has_outbound_request_on_input | `false` | → ssrf_generic SKIP |
| has_graphql_endpoint | `false` | → graphql_generic SKIP |
| has_xpath_parser | `false` | → xpath_generic SKIP |
| has_file_path_from_input | `false` | → directory_traversal SKIP |
| has_ldap_query | `false` | → ldap_generic SKIP |

**12 endpoint trovati** da `mapping`:
- `GET  /api/articles` — no auth
- `POST /api/register` — params: username, password, email (body JSON)
- `POST /api/login` — params: username, password (body JSON)
- `POST /api/donate` — params: price (body JSON)
- `POST /api/sell` — params: title, description, price, secret (body JSON)
- `POST /api/store/<int:article_id>/buy` — path param: article_id
- `POST /api/logout`
- (altri 5 — leggere `reports/Pwnzer0tt1Shop/endpoints_map.json` per il dettaglio completo)

---

## TODO List — Testing moduli

### FASE 0 — Setup e Bootstrap

- ✅ **[SETUP-1]** Build immagine Docker `ctf-recon-suite:latest` — 2026-07-10
- ✅ **[SETUP-2]** Avvio servizio target Pwnzer0tt1Shop — risponde 200 su porta 80
- ✅ **[SETUP-3]** `target_url: "http://127.0.0.1:80"` impostato in `settings.json`
- ✅ **[MODULE-mapping]** `mapping` — **12 endpoint trovati**, `endpoints_map.json` prodotto correttamente
  - Bug trovato e fixato: `run()` non accettava `**kwargs` (crash in single-module mode)
  - Fix: aggiunto `**kwargs` a `modules/mapping/endpoint_parser.py:run()` e `orchestrator/stack_detector.py:run()`
- ✅ **[MODULE-stack_detector]** `stack_detector` — gira nel bootstrap, `detected_stack.json` prodotto (vedi tabella stack sopra)

---

### FASE 1 — Discovery (statici / basso impatto)

- 🔲 **[MODULE-semgrep]** SAST sul codice sorgente
- 🔲 **[MODULE-ripgrep]** Grep su pattern pericolosi nel sorgente
- 🔲 **[MODULE-jsluice]** Estrae URL/segreti da file JS
- 🔲 **[MODULE-trufflehog]** Cerca segreti/credenziali — ATTESO ATTIVO (`db_present_in_domain=true`)
- 🔲 **[MODULE-gitleaks]** Cerca segreti nel repo git — ATTESO ATTIVO (`db_present_in_domain=true`)
- 🔲 **[MODULE-nuclei]** Scanner misconfig — richiede `target_url`

---

### FASE 2 — Injection (attivi — servizio target richiesto)

- 🔲 **[MODULE-sqlmap]** ⭐ PROSSIMO DA TESTARE
  - Trigger soddisfatto: `has_sql_queries=true`
  - Endpoint candidati: `/api/login`, `/api/register`, `/api/donate`, `/api/sell`
  - Comando: `python3 start.py --path=... --module=sqlmap --no-target --verbose --dev`

- 🔲 **[MODULE-ghauri]** — trigger soddisfatto: `has_sql_queries=true`
- 🔲 **[MODULE-sstimap]** — Flask+Jinja2, possibile SSTI
- 🔲 **[MODULE-commix]** — Command Injection
- 🔲 **[MODULE-nosqli]** — trigger: `has_nosql=true AND NOT has_sql_queries` → SKIP atteso (entrambi true)
- 🔲 **[MODULE-ssrf_generic]** — trigger non soddisfatto → SKIP atteso
- 🔲 **[MODULE-graphql_generic]** — trigger non soddisfatto → SKIP atteso
- 🔲 **[MODULE-xpath_generic]** — trigger non soddisfatto → SKIP atteso
- 🔲 **[MODULE-directory_traversal]** — trigger non soddisfatto → SKIP atteso
- 🔲 **[MODULE-ldap_generic]** — trigger non soddisfatto → SKIP atteso

---

### FASE 3 — Auth

- ⏭️ **[MODULE-jwt_tool]** — `uses_jwt=false` → SKIP atteso

---

### FASE 4 — Lang-specific

- 🔲 **[MODULE-fickling]** — `has_eval_on_input=false` → SKIP atteso
- ⏭️ **[MODULE-phpggc]** — `has_php=false` → SKIP
- ⏭️ **[MODULE-symfony]** — `has_symfony_twig=false` → SKIP
- 🔲 **[MODULE-nodejsscan]** — verificare se il frontend JS viene rilevato

---

### FASE 5 — Upload & File

- ⏭️ **[MODULE-slipit]** — `has_file_upload=false` → SKIP
- ⏭️ **[MODULE-exiftool]** — `has_file_upload=false` → SKIP
- ⏭️ **[MODULE-polyglot]** — `has_file_upload=false` → SKIP

---

### FASE 6 — gRPC & XXE

- ⏭️ **[MODULE-grpcurl]** — `has_grpc=false` → SKIP
- 🔲 **[MODULE-xxeexploiter]** — ungated, da testare

---

## Anomalie e bug riscontrati

| # | Modulo | Descrizione bug | File | Stato fix |
|---|--------|----------------|------|-----------|
| 1 | `mapping`, `stack_detector` | `run()` mancava `**kwargs` → `TypeError` in single-module mode quando il core passa `stack=` e `endpoints=` | `modules/mapping/endpoint_parser.py:521`, `orchestrator/stack_detector.py:405` | ✅ Fixato 2026-07-10 |

---

## Findings interessanti sul target Pwnzer0tt1Shop

| Modulo | Tipo | File:Riga | Endpoint | Dettaglio |
|--------|------|-----------|----------|-----------|
| mapping | endpoint | backend/app.py:158 | POST /api/sell | Parametro `secret` in body JSON — interessante |
| mapping | endpoint | backend/app.py:100 | POST /api/login | Credenziali in chiaro nel body — candidato SQLi |
| mapping | endpoint | backend/app.py:135 | POST /api/donate | Parametro `price` — possibile manipolazione valori |
