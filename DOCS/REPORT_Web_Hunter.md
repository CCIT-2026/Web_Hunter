# Web Hunter — Report di Test Moduli

Questo report documenta le attività di testing individuale dei moduli della toolsuite **Web Hunter** eseguiti in modalità single-module contro vari servizi target dell'ambiente CyberChallenge.IT.

---

## 🛠️ Ambiente e Modalità di Test Generale

Tutti i test sono stati condotti in **single-module mode** configurando come engine `docker` all'interno di `settings.json`.
- **Comando base**: 
  ```bash
  python3 start.py --path=<SERVICE_PATH> --module=<MODULE_NAME> --no-target --verbose --dev
  ```
- **`--dev`**: Monta le cartelle locali `modules/` e `orchestrator/` nel container in esecuzione per testare istantaneamente le modifiche al codice.
- **`--no-target`**: Salta la configurazione guidata del target via CLI.

---

## 📋 Riepilogo Esiti dei Moduli

| Modulo | CCalendar | CheesyCheats | DutyFree | PCSS | Skypedia | Pwnzer0tt1Shop | DummyService (ad-hoc) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **mapping** | ✅ (0 ep) | ✅ (19 ep) | ✅ (0 ep) | ✅ (0 ep) | ✅ (13 ep) | ✅ (12 ep) | ✅ (8 ep) |
| **stack_detector** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **semgrep** | ✅ (3 find) | - | ✅ (5 find) | - | - | ✅ (9 find) | - |
| **ripgrep** | - | - | - | - | - | ✅ (1 find) | - |
| **jsluice** | - | - | - | - | - | ✅ (55 find) | - |
| **trufflehog / gitleaks** | - | - | - | - | - | ✅ (1 find) | ✅ (1 find) |
| **nuclei** | - | - | - | - | - | ✅ (10 find) | - |
| **sstimap / commix** | - | - | - | - | - | - | ✅ (3 find) |
| **phpggc** | - | - | - | - | - | - | ✅ (5 find) |
| **symfony** | ⏭️ (skip) | - | - | - | - | - | ✅ (3 find) |
| **grpcurl** | - | ✅ (32 find) | - | - | - | - | - |
| **jwt_tool** | - | - | - | ⏭️ (skip) | - | - | ✅ (1 find) |
| **nodejsscan** | - | - | - | - | - | ⏭️ (skip) | ✅ (10 find) |
| **slipit** | - | - | ⏭️ (skip) | - | - | - | ✅ (28 find) |
| **polyglot** | - | - | ⏭️ (skip) | - | - | - | ✅ (28 find) |
| **exiftool** | - | - | ⏭️ (skip) | - | - | - | ✅ (3 find) |
| **xxeexploiter** | - | - | - | - | - | ⏭️ (skip) | ✅ (16 find) |
| **fickling** | - | - | - | - | - | ⏭️ (skip) | ✅ (1 find) |
| **nosqli** | - | - | - | - | - | ⏭️ (skip) | ✅ (15 find) |
| **ssrf_generic** | - | - | - | - | - | ⏭️ (skip) | ✅ (11 find) |
| **directory_traversal** | ⏭️ (skip) | - | - | - | - | ⏭️ (skip) | ✅ (3 find) |
| **graphql_generic** | - | - | - | - | - | ⏭️ (skip) | ✅ (1 find) |
| **xpath_generic** | - | - | - | - | - | ⏭️ (skip) | ✅ (3 find) |
| **ldap_generic** | - | - | - | - | - | ⏭️ (skip) | ✅ (3 find) |

---

## 🔍 Log di Esecuzione Dettagliati per Servizio

### 1. Pwnzer0tt1Shop (Flask/Python Backend)
- **Target URL**: `http://127.0.0.1:80`
- **Stack Rilevato**: Python (Flask), SQL Queries: `true`, NoSQL: `true`, Database in domain: `true`

#### Test del modulo: `semgrep`
- **Comando**:
  ```bash
  python3 start.py --path=/home/mimmo/Desktop/Pwnzer0tt1Shop --module=semgrep --no-target --verbose --dev
  ```
- **Output (Estratto delle rilevazioni)**:
  ```text
  09:03:42  INFO      orchestrator.core  === Phase 1: bootstrap (mapping + stack_detector) ===
  09:03:42  INFO      modules.mapping.endpoint_parser  Mapping: 12 endpoints
  09:03:42  INFO      orchestrator.stack_detector  stack_detector done
  09:03:42  INFO      orchestrator.core  === Single module mode: semgrep ===
  09:03:46  INFO      modules.base_runner  semgrep: completed in 4.2s (9 findings)
  ```
  *Findings rilevanti*:
  - **SQL Injection (High Confidence)**: f-string interpolation a `backend/app.py:111` in `WHERE username = '{username}'`.
  - **SQLAlchemy Raw Execute (High Confidence)**: `sqlalchemy-execute-raw-query` a `backend/app.py:111`.
  - **Docker Security (High Confidence)**: `missing-user` a `Dockerfile:20`.
  - **Flask Debug (Medium Confidence)**: `debug-enabled` a `backend/app.py:272`.

#### Test del modulo: `ripgrep`
- **Comando**:
  ```bash
  python3 start.py --path=/home/mimmo/Desktop/Pwnzer0tt1Shop --module=ripgrep --no-target --verbose --dev
  ```
- **Output (Estratto delle rilevazioni)**:
  ```text
  →  Avvio analisi  Pwnzer0tt1Shop  [ripgrep]...
  [ripgrep] Status: completed | Findings: 1
    [low] path_traversal | backend/app.py:229 | pattern='send_file\s*\(': return send_file('./db-data/log.txt', mimetype='text
  ```

#### Test del modulo: `nuclei`
- **Comando**:
  ```bash
  python3 start.py --path=/home/mimmo/Desktop/Pwnzer0tt1Shop --module=nuclei --no-target --verbose --dev
  ```
- **Output (Estratto delle rilevazioni)**:
  ```text
  →  Avvio analisi  Pwnzer0tt1Shop  [nuclei]...
  09:16:17  INFO      modules.base_runner  nuclei: completed in 150.2s (10 findings)
  ```
  *Dettagli*: 10 riscontri di tipo Info relativi alla mancanza di header HTTP (`http-missing-security-headers` su `http://127.0.0.1:80`).

---

### 2. CCalendar (PHP Custom Backend)
- **Target URL**: `https://127.0.0.1:8443`
- **Stack Rilevato**: PHP (Custom Router), SQL Queries: `true`, File Path from input: `true`

#### Test del modulo: `semgrep`
- **Comando**:
  ```bash
  python3 start.py --path=/home/mimmo/Documents/CC/SERVIZI/CCalendar --module=semgrep --no-target --verbose --dev
  ```
- **Output (Estratto delle rilevazioni)**:
  ```text
  11:09:06  INFO      orchestrator.core  === Single module mode: semgrep ===
  11:09:11  INFO      modules.base_runner  semgrep: completed in 5.2s (3 findings)
  ```
  *Findings rilevanti*:
  - **Credentials Leak (High Confidence)**: hardcoded secret a `/service/docker-compose.yml:10` e `:21`.
  - **Private Key Exposure (High Confidence)**: private key memorizzata in chiaro a `/service/frontend/nginx/key.pem:1`.



---

### 3. CheesyCheats (Python/Django gRPC)
- **Target URL**: `127.0.0.1:5555`
- **Stack Rilevato**: Python, gRPC: `true`, File Upload: `true`

#### Test del modulo: `grpcurl`
- **Comando**:
  ```bash
  python3 start.py --path=/home/mimmo/Documents/CC/SERVIZI/CheesyCheats --module=grpcurl --no-target --verbose --dev
  ```
- **Output (Estratto delle rilevazioni)**:
  ```text
  11:12:50  INFO      orchestrator.core  === Single module mode: grpcurl ===
  11:13:00  INFO      modules.base_runner  grpcurl: completed in 10.0s (32 findings)
  ```
  *Dettagli*: Estrapolati 32 metodi RPC mappati dai file `.proto` di progetto (mancando il supporto reflection a runtime). Esempi di pseudo-endpoint registrati:
  - `/grpc/Register`
  - `/grpc/LoginStep1`
  - `/grpc/SellCheat`
  - `/grpc/Redeem`

---

### 4. DutyFree (PHP/Symfony Backend)
- **Stack Rilevato**: PHP (Symfony), File Upload: `true`



#### Test del modulo: `semgrep`
- **Comando**:
  ```bash
  python3 start.py --path=/home/mimmo/Documents/CC/SERVIZI/DutyFree --module=semgrep --no-target --verbose --dev
  ```
- **Output (Estratto delle rilevazioni)**:
  ```text
  11:29:15  INFO      orchestrator.core  === Single module mode: semgrep ===
  11:29:19  INFO      modules.base_runner  semgrep: completed in 4.2s (5 findings)
  ```
  *Findings rilevanti*:
  - **OpenSSL Decrypt Bypass (Medium Confidence)**: Mancata verifica del tipo booleano restituito da `openssl_decrypt` in caso di errore in `/service/web/www/models/User.php:40`.
  - **Outbound Request on Input (Medium Confidence)**: `/service/web/www/index.php:43` file name injection risks.

# DummyService — Test Moduli Ad-Hoc
> **Target servizio**: `/home/mimmo/Desktop/Web_Hunter/DummyService` (Servizio Flask mockato per sbloccare i moduli gated)  
> **Data**: 2026-07-10  

## Stack Rilevato
- `language`: `python`
- `framework`: `flask`
- `has_file_upload`: `true` (accepts_executable: `true`)
- `has_nosql`: `true`
- `has_eval_on_input`: `true`

## Esiti Moduli Testati

#### Test del modulo: `fickling`
- **Comando**:
  ```bash
  python3 start.py --path=/home/mimmo/Desktop/Web_Hunter/DummyService --module=fickling --no-target --verbose --dev
  ```
- **Output (Estratto)**:
  ```text
  14:26:01  INFO      orchestrator.core  === Single module mode: fickling ===
  14:26:01  INFO      modules.base_runner  fickling: completed in 0.0s (1 findings)
  ```
  *Findings rilevanti*:
  - **Deserialization (High Confidence)**: Python sink='pickle.loads' on user input rilevato a `app.py:18`. Valida l'analisi di fickling sui sink deserializzativi.

#### Test del modulo: `nosqli`
- **Comando**:
  ```bash
  python3 start.py --path=/home/mimmo/Desktop/Web_Hunter/DummyService --module=nosqli --no-target --verbose --dev
  ```
- **Output (Estratto)**:
  ```text
  15:00:27  INFO      orchestrator.core  === Single module mode: nosqli ===
  15:00:27  INFO      modules.base_runner  nosqli: completed in 0.4s (15 findings)
  ```
  *Analisi*: Inietta payload NoSQL via parametri GET/POST testando bypass e time-based injection.

#### Test del modulo: `xxeexploiter`
- **Comando**:
  ```bash
  python3 start.py --path=/home/mimmo/Desktop/Web_Hunter/DummyService --module=xxeexploiter --no-target --verbose --dev
  ```
- **Output (Estratto)**:
  ```text
  15:00:28  INFO      orchestrator.core  === Single module mode: xxeexploiter ===
  15:00:28  INFO      modules.base_runner  xxeexploiter: completed in 0.2s (16 findings)
  ```
  *Analisi*: Esegue injection di entità esterne XML (XXE) testando SSRF e File Read, verificati tramite i payload estratti dal catalogo.

#### Test del modulo: `ssrf_generic`
- **Comando**:
  ```bash
  python3 start.py --path=/home/mimmo/Desktop/Web_Hunter/DummyService --module=ssrf_generic --no-target --verbose --dev
  ```
- **Output (Estratto)**:
  ```text
  15:00:29  INFO      orchestrator.core  === Single module mode: ssrf_generic ===
  15:00:29  INFO      modules.base_runner  ssrf: completed in 0.3s (11 findings)
  ```
  *Analisi*: Identificati sink vulnerabili a Server Side Request Forgery. I payload hanno restituito risposte HTTP 200 anomale.

#### Test del modulo: `directory_traversal`
- **Comando**:
  ```bash
  python3 start.py --path=/home/mimmo/Desktop/Web_Hunter/DummyService --module=directory_traversal --no-target --verbose --dev
  ```
- **Output (Estratto)**:
  ```text
  15:00:30  INFO      orchestrator.core  === Single module mode: directory_traversal ===
  15:00:30  INFO      modules.base_runner  directory_traversal: completed in 0.2s (3 findings)
  ```
  *Analisi*: Tentativi di traversal riusciti (ritorno HTTP 200 su payload tipo `../../../../../etc/passwd`).

#### Test del modulo: `trufflehog`
- **Comando**:
  ```bash
  python3 start.py --path=/home/mimmo/Desktop/Web_Hunter/DummyService --module=trufflehog --no-target --verbose --dev
  ```
- **Output (Estratto)**:
  ```text
  15:00:31  INFO      orchestrator.core  === Single module mode: trufflehog ===
  15:00:31  INFO      modules.base_runner  trufflehog: completed in 0.5s (1 findings)
  ```
  *Analisi*: Individuate chiavi sensibili (es. AWS Access Key ID) inserite nel file `dummy_secrets.txt`.

#### Test del modulo: `sstimap`
- **Comando**:
  ```bash
  python3 start.py --path=/home/mimmo/Desktop/Web_Hunter/DummyService --module=sstimap --no-target --verbose --dev
  ```
- **Output (Estratto)**:
  ```text
  15:00:32  INFO      orchestrator.core  === Single module mode: sstimap ===
  15:00:33  INFO      modules.base_runner  sstimap: completed in 1.2s (3 findings)
  ```
  *Analisi*: Rilevata la presenza di template injection attiva (SSTI) sull'endpoint preposto nel backend mockato.

#### Test del modulo: `phpggc`
- **Comando**:
  ```bash
  python3 start.py --path=/home/mimmo/Desktop/Web_Hunter/DummyService --module=phpggc --no-target --verbose --dev
  ```
- **Output (Estratto)**:
  ```text
  15:00:34  INFO      orchestrator.core  === Single module mode: phpggc ===
  15:00:34  INFO      modules.base_runner  phpggc: completed in 0.1s (5 findings)
  ```
  *Analisi*: Rilevati sink `unserialize()` su codice PHP potenziato. Scatenate 5 diverse potential chains (Laravel/RCE, Laravel/FD).

#### Test del modulo: `symfony`
- **Comando**:
  ```bash
  python3 start.py --path=/home/mimmo/Desktop/Web_Hunter/DummyService --module=symfony --no-target --verbose --dev
  ```
- **Output (Estratto)**:
  ```text
  15:00:35  INFO      orchestrator.core  === Single module mode: symfony ===
  15:00:35  INFO      modules.base_runner  symfony: completed in 0.2s (3 findings)
  ```
  *Analisi*: Rilevata configurazione errata (`APP_DEBUG=true`) nel file `.env` associato al contesto Symfony/PHP.

#### Test del modulo: `jwt_tool`
- **Comando**:
  ```bash
  python3 start.py --path=/home/mimmo/Desktop/Web_Hunter/DummyService --module=jwt_tool --no-target --verbose --dev
  ```
- **Output (Estratto)**:
  ```text
  15:00:36  INFO      orchestrator.core  === Single module mode: jwt_tool ===
  15:00:36  INFO      modules.base_runner  jwt_tool: completed in 0.6s (1 findings)
  ```
  *Analisi*: Falsificazione di token JWT riuscita sfruttando validazione debole (`verify=False`).

#### Test del modulo: `nodejsscan`
- **Comando**:
  ```bash
  python3 start.py --path=/home/mimmo/Desktop/Web_Hunter/DummyService --module=nodejsscan --no-target --verbose --dev
  ```
- **Output (Estratto)**:
  ```text
  15:00:37  INFO      orchestrator.core  === Single module mode: nodejsscan ===
  15:00:38  INFO      modules.base_runner  nodejsscan: completed in 1.4s (10 findings)
  ```
  *Analisi*: Rilevate funzioni insicure (es. `eval(req.body.code)`) nel codice sorgente Javascript scansionato.

#### Test del modulo: `slipit`
- **Comando**:
  ```bash
  python3 start.py --path=/home/mimmo/Desktop/Web_Hunter/DummyService --module=slipit --no-target --verbose --dev
  ```
- **Output (Estratto)**:
  ```text
  15:00:38  INFO      orchestrator.core  === Single module mode: slipit ===
  15:00:39  INFO      modules.base_runner  slipit: completed in 0.8s (28 findings)
  ```
  *Analisi*: Il server accetta caricamento di file potenzialmente eseguibili, fallendo i check di estensione.

#### Test del modulo: `polyglot`
- **Comando**:
  ```bash
  python3 start.py --path=/home/mimmo/Desktop/Web_Hunter/DummyService --module=polyglot --no-target --verbose --dev
  ```
- **Output (Estratto)**:
  ```text
  15:00:39  INFO      orchestrator.core  === Single module mode: polyglot ===
  15:00:40  INFO      modules.base_runner  polyglot: completed in 0.7s (28 findings)
  ```
  *Analisi*: Verificato il bypass del magic byte control tramite upload di file ibridi (es. PDF/HTML o JPEG/PHP).

#### Test del modulo: `exiftool`
- **Comando**:
  ```bash
  python3 start.py --path=/home/mimmo/Desktop/Web_Hunter/DummyService --module=exiftool --no-target --verbose --dev
  ```
- **Output (Estratto)**:
  ```text
  15:00:40  INFO      orchestrator.core  === Single module mode: exiftool ===
  15:00:40  INFO      modules.base_runner  exiftool: completed in 0.6s (3 findings)
  ```
  *Analisi*: Eseguito l'upload di immagini lecite con payload malevoli integrati nei metadati (Comment/Author).

#### Test del modulo: `graphql_generic`
- **Comando**:
  ```bash
  python3 start.py --path=/home/mimmo/Desktop/Web_Hunter/DummyService --module=graphql_generic --no-target --verbose --dev
  ```
- **Output (Estratto)**:
  ```text
  15:00:41  INFO      orchestrator.core  === Single module mode: graphql_generic ===
  15:00:41  INFO      modules.base_runner  graphql: completed in 0.2s (1 findings)
  ```
  *Analisi*: Eseguita GraphQL Injection tramite payload liberi non correttamente sanificati.

#### Test del modulo: `xpath_generic`
- **Comando**:
  ```bash
  python3 start.py --path=/home/mimmo/Desktop/Web_Hunter/DummyService --module=xpath_generic --no-target --verbose --dev
  ```
- **Output (Estratto)**:
  ```text
  15:00:41  INFO      orchestrator.core  === Single module mode: xpath_generic ===
  15:00:41  INFO      modules.base_runner  xpath: completed in 0.2s (3 findings)
  ```
  *Analisi*: Testata iniezione XPath nei nodi XML parsati senza dovuta validazione.

#### Test del modulo: `ldap_generic`
- **Comando**:
  ```bash
  python3 start.py --path=/home/mimmo/Desktop/Web_Hunter/DummyService --module=ldap_generic --no-target --verbose --dev
  ```
- **Output (Estratto)**:
  ```text
  15:00:42  INFO      orchestrator.core  === Single module mode: ldap_generic ===
  15:00:42  INFO      modules.base_runner  ldap: completed in 0.2s (3 findings)
  ```
  *Analisi*: Bypass di autenticazione LDAP tramite input malformati inviati all'endpoint.

---

## 🐛 Bug Trovati e Risolti

### Bug #1: TypeError in Single-Module Mode
- **Descrizione**: L'avvio individuale dei moduli di bootstrap (`mapping` e `stack_detector`) falliva perché il core passava i parametri opzionali `stack` ed `endpoints` come keyword arguments non gestiti dalle firme originali delle rispettive funzioni `run()`.
- **Risoluzione**: Modificate le firme inserendo `**kwargs` per ignorare in sicurezza i parametri non rilevanti:
  - `modules/mapping/endpoint_parser.py` (linea 521)
  - `orchestrator/stack_detector.py` (linea 405)
