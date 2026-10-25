# 🧪 WEB — Checklist Vulnerabilità (copertura tool)

> **Scopo.** Elenco esaustivo delle vulnerabilità web da coprire, incrociando gli **stack reali dei servizi di gara** (`SERVIZI/`) con le **classi già affrontate** nell'oracolo `WEB.md` e nei writeup del vault.
>
> **Come usarlo.** Usalo con chi conosce il tuo tool: per ogni riga chiedi se è **coperta** (rilevamento e/o exploiting), compilando la colonna `Coperto dal tool?` con ✅ / ⚠️ (parziale) / ❌ e il nome del componente/modulo che la gestisce. Alla fine avrai la mappa dei buchi.
>
> Legenda colonna *Dove*: `Flask` = Flask+Jinja2 (MySQL/PG/SQLAlchemy) · `Node` = Express (pg/sequelize/ejs/multer/tar/sharp/jsonwebtoken) · `Svelte` = SvelteKit+MySQL+libxmljs · `PHP` = PHP+Twig · `gRPC` = gRPC/pycryptodome · `*` = trasversale a tutti.

---

## Mappa servizi → stack → superficie principale

| Servizio | Stack | Superficie d'attacco tipica |
|---|---|---|
| CApp | Flask + Flask-MySQL | SQLi (query concatenate), session Flask |
| BoomThrow | Flask + pillow + qrcode | SSTI Jinja2, image parsing, pickle |
| ExCCel | Flask + SQLAlchemy + crypto-js (FE) | SQLi/ORM, crypto lato client |
| Pwnzer0tt1Shop | Flask + SQLAlchemy + bcrypt + session | Logic/IDOR, auth, SQLi |
| SeaOfHackerz | Flask + psycopg2 (Postgres) + pycryptodome | SQLi Postgres, crypto, APScheduler |
| CCForms | Express + ejs + sequelize + pg + jsonwebtoken | SSTI EJS, SQLi/ORM, JWT |
| Skypedia | Express + multer + pg + jsonwebtoken | File upload, SQLi, JWT |
| ControlTower | Express + sharp + tar/tar-stream + mqtt + pg + jwt | Zip/tar-slip, image/SSRF, MQTT, JWT |
| GadgetHorse | SvelteKit + libxmljs + mysql2 + jsonwebtoken + bcrypt | **XXE**, JWT alg-confusion, SQLi |
| DutyFree | PHP + Twig + keccak | **SSTI Twig / PHP object injection**, crypto |
| CheesyCheats | gRPC (Python) + pycryptodome + sqlitedict | gRPC auth bypass, crypto, SQLi sqlite |
| PCSS | Python + `jwt==0.5.4` | JWT (libreria datata) |

---

## 0. Recon / Information Disclosure

| Vulnerabilità / Tecnica | Dove | Coperto dal tool? |
|---|---|---|
| `.git/` esposto → recupero sorgenti | * | |
| `.env` / file di config esposti | * | |
| Source disclosure (`?source`, `.bak`, `~`, `php://filter`) | PHP/* | |
| Commenti HTML/JS, endpoint nascosti nei `.js` | * | |
| `robots.txt` / sitemap / file di backup | * | |
| Directory listing abilitato | * | |
| Errori verbosi / stack trace / **Flask debug mode + Werkzeug console (PIN)** | Flask | |
| Source map frontend (`.js.map`) → sorgente React/Svelte | Node/Svelte | |
| Swagger/OpenAPI o doc API esposte | * | |
| Credenziali di default / hardcoded nel sorgente | * | |

## 1. Path Traversal / LFI / RFI

| Vulnerabilità / Tecnica | Dove | Coperto dal tool? |
|---|---|---|
| Path traversal `../` (lettura file arbitrari) | * | |
| LFI (`include`) | PHP | |
| `php://filter/convert.base64-encode` (leak sorgente) | PHP | |
| Nginx **alias traversal** (`/static../`) | * | |
| LFI → RCE (log poisoning, `/proc/self/environ`, session, `pearcmd`) | PHP | |
| Null byte / path assoluto / doppio encoding | * | |
| RFI (include remoto) | PHP | |

## 2. SSRF — Server-Side Request Forgery

| Vulnerabilità / Tecnica | Dove | Coperto dal tool? |
|---|---|---|
| SSRF base (fetch verso rete interna) | Node/* | |
| Bypass filtro localhost (`0x7f..`, decimale, `127.1`, `[::1]`, `user@host`) | * | |
| SSRF via **redirect 302** | * | |
| **Parser inconsistency** (Orange Tsai) | * | |
| Gopher/protocol smuggling → redis/mysql/**mqtt** interni | Node | |
| SSRF via **image processing** (sharp/SVG) | Node | |
| SSRF via **XXE** | Svelte | |
| Cloud metadata (`169.254.169.254`) | * | |
| Blind SSRF → esfiltrazione OOB | * | |

## 3. Command Injection / RCE

| Vulnerabilità / Tecnica | Dove | Coperto dal tool? |
|---|---|---|
| Command injection diretta (`;` `|` `&` `$()` `` `` ``) | * | |
| Blind command injection (`${IFS}`, timing, OOB) | * | |
| **Argument/option injection** (tar `--checkpoint-action`, zip, ecc.) | Node | |
| Bypass spazi (`${IFS}`, `<`) | * | |
| Bypass filtri (globbing, quote, concatenazione) | * | |
| RCE via funzioni specifiche (`awk system()`, ecc.) | * | |
| Reverse shell / bind shell | * | |

## 4. Code Injection / Sandbox escape

| Vulnerabilità / Tecnica | Dove | Coperto dal tool? |
|---|---|---|
| Python `eval`/`exec` injection | Flask/gRPC | |
| Sandbox escape Python (`__import__`, `__builtins__`, subclasses) | Flask | |
| PHP `eval`/`create_function`/`assert` | PHP | |
| Node `vm`/`Function`/`child_process` injection | Node | |

## 5. SQL Injection

| Vulnerabilità / Tecnica | Dove | Coperto dal tool? |
|---|---|---|
| Auth bypass (`' OR '1'='1`) | * | |
| Union-based (MySQL) | Flask/Node/Svelte | |
| Union-based (Postgres) | Node/Flask(PG) | |
| Boolean blind | * | |
| Time-based blind (`SLEEP`, `pg_sleep`) | * | |
| Error-based | * | |
| Stacked queries | * | |
| Second-order SQLi | * | |
| **WAF bypass (De Morgan / commenti / case)** | * | |
| File read (`LOAD_FILE`, PG `COPY`) | * | |
| File write (`INTO OUTFILE`) / webshell | * | |
| **Postgres `COPY ... FROM PROGRAM` → RCE** | Node/Flask(PG) | |
| Escape bypass (backslash, tipo Store98) | * | |
| ORM injection (Sequelize / SQLAlchemy raw / kysely) | Node/Flask/Svelte | |
| SQLi su sqlite (sqlitedict) | gRPC | |

## 6. Altre injection

| Vulnerabilità / Tecnica | Dove | Coperto dal tool? |
|---|---|---|
| NoSQL injection (operator injection) | Node | |
| LDAP / XPath injection | * | |
| CRLF / header injection | * | |

## 7. XSS — Cross-Site Scripting

| Vulnerabilità / Tecnica | Dove | Coperto dal tool? |
|---|---|---|
| Reflected XSS | * | |
| Stored XSS | * | |
| DOM-based XSS | Node/Svelte(FE) | |
| Bypass filtri (tag/attributo/keyword/encoding) | * | |
| **XSS via header** (tipo Super PHP I18N) | * | |
| XSS con escape unicode (tipo JPASTA) | * | |
| CSP bypass | * | |
| mutation XSS (mXSS) | * | |
| Furto cookie/sessione → account admin | * | |
| XSS via SVG / file upload | Node | |

## 8. CSRF

| Vulnerabilità / Tecnica | Dove | Coperto dal tool? |
|---|---|---|
| CSRF classico | * | |
| Bypass token / **rolling token** (tipo Rolling CSRF Chain) | * | |
| Bypass SameSite | * | |
| JSON CSRF / content-type trick | Node | |
| Login/logout CSRF | * | |

## 9. Broken Access Control / IDOR / Logic

| Vulnerabilità / Tecnica | Dove | Coperto dal tool? |
|---|---|---|
| IDOR (riferimento diretto a oggetti) | * | |
| **EAR** (Execution After Redirect) | Flask/PHP | |
| Parameter tampering (tipo Thinking Fruit) | * | |
| Mass assignment / over-posting | Node/Flask | |
| Privilege escalation (role/flag tampering) | * | |
| Forced browsing verso `/admin` | * | |
| Business logic (prezzi, quantità negative, sconti) | Flask(shop) | |
| **Race condition / TOCTOU** (double-spend) | * | |

## 10. Auth / Session / JWT

| Vulnerabilità / Tecnica | Dove | Coperto dal tool? |
|---|---|---|
| JWT `alg:none` | Node/Svelte/PCSS | |
| JWT **alg confusion RS256→HS256** (firma con public key) | Node/Svelte | |
| JWT weak secret cracking (hashcat/jwt_tool) | Node/Svelte/PCSS | |
| JWT `kid` injection (path traversal / SQLi nel kid) | Node | |
| JWT `jku`/`x5u` header injection | Node | |
| Vulnerabilità libreria `jwt==0.5.4` (datata) | PCSS | |
| **Flask session forge** (SECRET_KEY debole → flask-unsign) | Flask | |
| Session fixation / prediction | * | |
| Password reset flaw (host header, token debole) | * | |
| Logic su timestamp/streak (tipo 5 Days Streak) | * | |
| bcrypt: truncation a 72 byte / timing | Node/Flask | |

## 11. File Upload / Archivi

| Vulnerabilità / Tecnica | Dove | Coperto dal tool? |
|---|---|---|
| Unrestricted upload → webshell | Node(multer)/PHP | |
| Bypass estensione / MIME / **magic bytes** | Node/PHP | |
| Path traversal nel filename | Node | |
| **Zip-slip** | Node | |
| **Tar-slip** (tar/tar-stream) | Node(ControlTower) | |
| Symlink dentro archivio (tipo ZipZap) | * | |
| Option/argument injection in tool di archiviazione | Node | |
| File polyglot | * | |
| Image parsing (sharp/pillow/ImageMagick) → RCE/SSRF | Node/Flask | |
| SVG → XSS/XXE | Node | |

## 12. Deserializzazione / Gadget chains

| Vulnerabilità / Tecnica | Dove | Coperto dal tool? |
|---|---|---|
| Python **pickle** → RCE | Flask/gRPC | |
| Flask session pickle | Flask | |
| PHP object injection / **phpggc gadget (Twig)** | PHP | |
| Node deserialization / **prototype pollution** → RCE | Node | |

## 13. SSTI — Server-Side Template Injection

| Vulnerabilità / Tecnica | Dove | Coperto dal tool? |
|---|---|---|
| **Jinja2** SSTI → RCE | Flask | |
| **Twig** SSTI → RCE | PHP(DutyFree) | |
| **EJS** SSTI → RCE | Node(CCForms) | |
| Detection SSTI + sandbox escape | * | |

## 14. XXE / XML

| Vulnerabilità / Tecnica | Dove | Coperto dal tool? |
|---|---|---|
| **XXE file read** (libxmljs) | Svelte(GadgetHorse) | |
| XXE → SSRF | Svelte | |
| XXE OOB (external DTD / esfiltrazione) | Svelte | |
| XInclude | Svelte | |
| Billion laughs (DoS) | Svelte | |

## 15. Attacchi a livello HTTP

| Vulnerabilità / Tecnica | Dove | Coperto dal tool? |
|---|---|---|
| HTTP Parameter Pollution (HPP) | * | |
| HTTP Request Smuggling (CL.TE / TE.CL) | * | |
| Host header injection (reset poisoning / routing) | * | |
| Web cache poisoning | * | |
| CRLF / response splitting | * | |
| Open redirect (anche come primitiva SSRF/OAuth) | * | |

## 16. Node/JS-specific

| Vulnerabilità / Tecnica | Dove | Coperto dal tool? |
|---|---|---|
| **Prototype pollution** (`__proto__` in JSON/merge/qs) | Node | |
| Prototype pollution → SSTI/RCE gadget | Node | |
| ReDoS (regex catastrofica) | Node/* | |

## 17. Crypto lato web (servizi con pycryptodome / keccak / crypto-js)

| Vulnerabilità / Tecnica | Dove | Coperto dal tool? |
|---|---|---|
| Padding oracle (CBC) | Flask/gRPC/PHP | |
| Token/nonce predicibili (RNG debole) | * | |
| Hash length extension | * | |
| ECB pattern / IV reuse | * | |
| Bypass firma / MAC (HMAC misuse) | * | |

## 18. gRPC-specific (CheesyCheats)

| Vulnerabilità / Tecnica | Dove | Coperto dal tool? |
|---|---|---|
| gRPC **reflection** → enumerazione servizi/metodi | gRPC | |
| Metodi senza auth / interceptor bypassabile | gRPC | |
| Manipolazione metadata / message tampering | gRPC | |

## 19. Protocolli/servizi collaterali

| Vulnerabilità / Tecnica | Dove | Coperto dal tool? |
|---|---|---|
| **MQTT** abuse (pub/sub non autenticato, topic injection) | Node(ControlTower) | |
| CORS misconfiguration (origin riflessa / `null`) | Node/* | |
| WebSocket hijacking / mancata origin-check | * | |
| GraphQL (introspection / batching) — se presente | * | |

---

## Come compilare la colonna "Coperto dal tool?"

- **✅ pieno** — il tool rileva **e** aiuta a sfruttare la classe (es. modulo dedicato / payload automatici).
- **⚠️ parziale** — rileva ma non sfrutta, o copre solo una variante.
- **❌ scoperto** — nessun supporto: candidato da aggiungere al tool o da fare a mano con `WEB.md`.

> Riferimenti incrociati: teoria/payload di ogni classe → sezioni corrispondenti in `WEB.md`; casi reali già risolti → tabella `WEB.md §16` e `CCHEATSHEET/WRITEUPS/Web/`.
