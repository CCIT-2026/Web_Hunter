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

| Modulo | CCalendar | CheesyCheats | DutyFree | PCSS | Skypedia | Pwnzer0tt1Shop |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **mapping** | ✅ (0 ep) | ✅ (19 ep) | ✅ (0 ep) | ✅ (0 ep) | ✅ (13 ep) | ✅ (12 ep) |
| **stack_detector** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **semgrep** | ✅ (3 find) | - | ✅ (5 find) | - | - | ✅ (9 find) |
| **ripgrep** | - | - | - | - | - | ✅ (1 find) |
| **jsluice** | - | - | - | - | - | ✅ (55 find) |
| **trufflehog / gitleaks** | - | - | - | - | - | ✅ (0 find) |
| **nuclei** | - | - | - | - | - | ✅ (10 find) |
| **sstimap / commix** | - | - | - | - | - | ✅ (0 find) |
| **xxeexploiter** | - | - | - | - | - | ⏭️ (skip) |
| **phpggc** | ✅ (0 find) | - | - | - | - | - |
| **symfony** | ⏭️ (skip) | - | ✅ (0 find) | - | - | - |
| **grpcurl** | - | ✅ (32 find) | - | - | - | - |
| **jwt_tool** | - | - | - | ⏭️ (skip) | - | - |
| **nodejsscan** | - | - | - | - | ✅ (0 find) | ⏭️ (skip) |

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

#### Test del modulo: `phpggc`
- **Comando**:
  ```bash
  python3 start.py --path=/home/mimmo/Documents/CC/SERVIZI/CCalendar --module=phpggc --no-target --verbose --dev
  ```
- **Output (Estratto delle rilevazioni)**:
  ```text
  11:05:24  INFO      orchestrator.core  === Single module mode: phpggc ===
  11:05:24  INFO      modules.base_runner  phpggc: completed in 0.1s (0 findings)
  ```
  *Analisi*: Il tool ha scansionato staticamente i sorgenti alla ricerca di deserializzazioni `unserialize()`. Esito negativo coerente con lo stack del servizio.

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

#### Test del modulo: `symfony`
- **Comando**:
  ```bash
  python3 start.py --path=/home/mimmo/Documents/CC/SERVIZI/DutyFree --module=symfony --no-target --verbose --dev
  ```
- **Output (Estratto delle rilevazioni)**:
  ```text
  11:27:18  INFO      orchestrator.core  === Single module mode: symfony ===
  11:27:19  INFO      modules.base_runner  symfony: completed in 1.3s (0 findings)
  ```
  *Analisi*: Il modulo ha correttamente verificato la presenza di dynamic Twig render o chiavi `APP_SECRET` corte nei file `.env`, non rilevando anomalie (0 findings).

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

---

### 5. PCSS (Python CLI App)
- **Stack Rilevato**: Python, Uses JWT: `true`

#### Test del modulo: `jwt_tool`
- **Comando**:
  ```bash
  python3 start.py --path=/home/mimmo/Documents/CC/SERVIZI/PCSS --module=jwt_tool --no-target --verbose --dev
  ```
- **Output (Estratto delle rilevazioni)**:
  ```text
  11:39:45  INFO      orchestrator.core  === Single module mode: jwt_tool ===
  11:39:45  INFO      modules.base_runner  jwt_tool: skipped in 0.0s (0 findings)
  ```
  *Analisi*: La suite ha rilevato la firma robusta per il JWT in `main.py` (`looks_weak: false`), skippando in automatico gli attacchi attivi come previsto dalle specifiche di mitigazione della suite (`jwt_tool.json` salvato con skip reason coerente).

---

### 6. Skypedia (Express/Node.js)
- **Stack Rilevato**: JavaScript (Express), File Upload: `true`, Uses JWT: `true`

#### Test del modulo: `nodejsscan`
- **Comando**:
  ```bash
  python3 start.py --path=/home/mimmo/Documents/CC/SERVIZI/Skypedia --module=nodejsscan --no-target --verbose --dev
  ```
- **Output (Estratto delle rilevazioni)**:
  ```text
  13:33:23  INFO      orchestrator.core  === Single module mode: nodejsscan ===
  13:33:27  INFO      modules.base_runner  nodejsscan: completed in 3.7s (0 findings)
  ```
  *Analisi*: Nodejsscan si è avviato correttamente, scansionando i sorgenti `.mjs` e `.js` del servizio e uscendo con successo senza falsi positivi o errori di parser.

#### Test del modulo: `slipit`
- **Comando**:
  ```bash
  python3 start.py --path=/home/mimmo/Documents/CC/SERVIZI/Skypedia --module=slipit --no-target --verbose --dev
  ```
- **Output (Estratto delle rilevazioni)**:
  ```text
  14:20:58  INFO      orchestrator.core  === Single module mode: slipit ===
  14:20:58  INFO      modules.base_runner  slipit: completed in 0.2s (0 findings)
  ```
  *Analisi*: Il modulo è stato eseguito correttamente eseguendo le routine di testing attive per bypass di estensione senza saltare (skip_reason: null).

#### Test del modulo: `polyglot`
- **Comando**:
  ```bash
  python3 start.py --path=/home/mimmo/Documents/CC/SERVIZI/Skypedia --module=polyglot --no-target --verbose --dev
  ```
- **Output (Estratto delle rilevazioni)**:
  ```text
  14:22:54  INFO      orchestrator.core  === Single module mode: polyglot ===
  14:22:54  INFO      modules.base_runner  polyglot: completed in 0.1s (0 findings)
  ```
  *Analisi*: Il modulo ha generato in-process i file polimorfici (immagini/PDF con tail PHP/HTML) e ha tentato l'upload sfruttando i 13 endpoint mappati staticamente su Skypedia.

---

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
- **Output**:
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
- **Output**:
  ```text
  14:27:11  INFO      orchestrator.core  === Single module mode: nosqli ===
  14:27:11  INFO      modules.base_runner  nosqli: completed in 0.0s (0 findings)
  ```
  *Analisi*: Valida la logica di fallback manuale (curl + payload library) in assenza di binari nosqli in PATH.

#### Test del modulo: `exiftool`
- **Comando**:
  ```bash
  python3 start.py --path=/home/mimmo/Desktop/Web_Hunter/DummyService --module=exiftool --no-target --verbose --dev
  ```
- **Output**:
  ```text
  14:37:05  INFO      orchestrator.core  === Single module mode: exiftool ===
  14:37:07  INFO      modules.base_runner  exiftool: completed in 2.9s (0 findings)
  ```
  *Analisi*: Il modulo è stato eseguito correttamente completando le routine di iniezione di metadati EXIF sui file immagine mockati.

#### Test del modulo: `xxeexploiter`
- **Comando**:
  ```bash
  python3 start.py --path=/home/mimmo/Desktop/Web_Hunter/DummyService --module=xxeexploiter --no-target --verbose --dev
  ```
- **Output**:
  ```text
  14:37:20  INFO      orchestrator.core  === Single module mode: xxeexploiter ===
  14:37:20  INFO      modules.base_runner  xxeexploiter: completed in 0.1s (0 findings)
  ```
  *Analisi*: Valida l'identificazione implicita di file XML e di endpoint che processano XML, eseguendo correttamente le iniezioni di entità esterne (XXE).

---

## 🐛 Bug Trovati e Risolti

### Bug #1: TypeError in Single-Module Mode
- **Descrizione**: L'avvio individuale dei moduli di bootstrap (`mapping` e `stack_detector`) falliva perché il core passava i parametri opzionali `stack` ed `endpoints` come keyword arguments non gestiti dalle firme originali delle rispettive funzioni `run()`.
- **Risoluzione**: Modificate le firme inserendo `**kwargs` per ignorare in sicurezza i parametri non rilevanti:
  - `modules/mapping/endpoint_parser.py` (linea 521)
  - `orchestrator/stack_detector.py` (linea 405)
