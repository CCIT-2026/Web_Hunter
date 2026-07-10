# CTF A/D Recon Suite — Stato del progetto
> **Aggiornato: 2026-07-10 — sessione 3**

---

## Architettura generale

```
HOST
├── start.py                  ← orchestratore host-side
│   ├── avvia il servizio target (interattivo)
│   ├── builda l'immagine docker/podman
│   └── lancia il container di analisi
│
└── Container di analisi
    ├── /service      ← sorgente del servizio bersaglio (bind-mount ro)
    ├── /reports      ← output (bind-mount rw)
    └── /app          ← suite (COPY nel Dockerfile)
        ├── orchestrator/core.py   ← pipeline
        └── modules/               ← runner individuali
```

Il codice dei moduli è **baked nell'immagine** al build. Per testare modifiche senza rebuild: `--dev`.

---

## Flag di start.py

| Flag | Comportamento |
|---|---|
| `--path=PATH` | Path del servizio (altrimenti chiede) |
| `--module=NAME` | Runna solo quel modulo (es. `--module=sqlmap`) |
| `--rebuild` | Clean + build `--no-cache` prima di avviare |
| `--dev` | Monta `./modules/` e `./orchestrator/` sull'immagine — testa senza rebuild |
| `--no-target` | Salta l'avvio interattivo del servizio target |
| `--clean` | Rimuove container e immagine ctf-recon-*, prune dangling layers |
| `--clone=URL` | Clona il repo report di un collega |
| `--verbose` | Mostra stdout/stderr di tutti i tool (docker build, container, compose) |
| `--debug` | Dump compatto variabili chiave a ogni step — senza stdout tool |
| `--debug --verbose` | Dump variabili + stdout tool |

I messaggi colorati (`→` / `✓` / `⚠` / `✗`) sono **sempre visibili** indipendentemente dai flag.

---

## Moduli e output

| Modulo | Tipo | Richiede servizio attivo? | Output |
|---|---|---|---|
| semgrep | statico | No | `semgrep.json` |
| ripgrep | statico | No | `ripgrep.json` |
| sqlmap | dinamico | **Sì** | `sqlmap.json` |
| ghauri | dinamico | **Sì** | `ghauri.json` |
| nuclei | dinamico | **Sì** | `nuclei.json` |
| jsluice | statico | No | `jsluice.json` |
| trufflehog / gitleaks | statico | No | `*.json` |

I moduli dinamici leggono `settings["target_url"]` e ci costruiscono le URL degli endpoint da `endpoints_map.json`.

---

## Modifiche apportate — sessione 1 (precedente)

### `modules/discovery/semgrep_runner.py`
- **Bug:** numeri di riga sbagliati — senza login cloud `extra.lines = "requires login"` e `start.line` contava solo righe non-vuote.
- **Fix:** `_line_from_offset()` — usa `start.offset` (byte offset, sempre presente) → `text[:offset].count("\n") + 1`.
- **Stato:** implementato, non ancora verificato su run reale.

### `modules/reporting/markdown_report.py`
- Rimosso `mapping` da `_SECTION_ORDER` (era renderizzato doppio).
- Aggiunto ASCII logo da `assets/.logo/ascii_art.txt`.
- Rimossi redirect "N findings — vedi §..." — tutti i findings appaiono inline.
- Aggiunta `_render_findings_grouped(findings, lines, *, show_source)` — rendering gerarchico priorità → tipo per ogni sezione.
- Sezione "Findings non verificabili automaticamente" diventa riepilogo cross-modulo con `show_source=True`.

### `Dockerfile`
- Aggiunta copia logo: `COPY assets/.logo/ascii_art.txt /assets/.logo/ascii_art.txt`.

---

## Modifiche apportate — sessione 2 (precedente)

### `modules/mapping/endpoint_parser.py`
- **Bug:** `params: []` per tutti gli endpoint POST — il parser estraeva solo parametri dal template URL, non dal corpo del handler.
- **Fix:** `_scan_handler_params()` — scansiona le righe del handler cercando accessi diretti (`request.form.get`, `request.json["x"]`, `request.get_json().get()`, ecc.) e il pattern a variabile intermedia (`data = request.get_json()` → `data.get("username")`). Si ferma alla prossima `def`/`@`/`class` a indentazione zero.
- **Integrato in:** `_FlaskExtractor`, `_FastApiExtractor`, `_ExpressExtractor`.
- **Fix aggiuntivo:** `_path_params()` riscritta con `seen` set per evitare duplicati su route tipo `/api/store/<int:article_id>/buy`.
- **Stato:** implementato, testato con smoke test sintetici, **non verificato su run reale**.

### `modules/injection/sqlmap_runner.py`
- **Bug 1:** `--format=JSON` inesistente in sqlmap → findings sempre vuoti.
- **Bug 2:** body mandato come `application/x-www-form-urlencoded` su app che usa `request.get_json()` → baseline rotta.
- **Fix:** parsing stdout (`"Parameter: X"` / `"Type: ..."` / `"is vulnerable"`); body JSON se `encoding: "json"` rilevato dall'endpoint_parser.
- **Stato:** implementato, **non verificato su run reale**.

### `orchestrator/core.py`
- **Bug 1 (sessione 1):** con `--module=NAME` il report.md non veniva generato.
- **Fix:** aggiunta chiamata a `_generate_markdown_report()` alla fine di `_run_single()`.
- **Bug 2 (sessione 2):** `_run_bootstrap()` catturava solo `ImportError` — qualsiasi altra eccezione crashava il container prima che i moduli girassero.
- **Fix:** `except ImportError` → `except Exception` con `logger.exception(...)`.

---

## Modifiche apportate — sessione 3 (questa)

### `start.py` — layer di output colorato
- **Aggiunto:**
  - `_verbose` / `_debug` — pre-parsati da `sys.argv` a livello modulo (prima di argparse)
  - `_C` — classe ANSI, si autodisabilita se stdout non è un TTY
  - `step()` / `ok()` / `warn()` / `err()` — sempre stampati, icona colorata
  - `dbg(**kwargs)` — dump `key=repr(val)` su una riga, solo con `--debug`
  - `run_cmd(cmd, *, capture, cwd, shell)` — sopprime output per default, lascia fluire con `--verbose`; logga il comando con `--debug`
  - `run_interactive(cmd)` — per comandi approvati dall'utente: output sempre visibile
- **Tutti i `print()` e `subprocess.run()` diretti rimpiazzati** con le funzioni sopra.
- **Bonus:** se build fallisce senza `--verbose`, appare hint automatico `⚠ Riavvia con --verbose per i dettagli`.

### Diagnosi bug sqlmap — identificati, **non ancora fixati**

Tre bug sovrapposti che spiegano `findings: []` su servizi con SQLi confermata da semgrep:

**Bug A — critico: fallback `target_url` mai attivo** (`sqlmap_runner.py:28`, `ghauri_runner.py:27`)
```python
# Attuale — SBAGLIATO: se "target_url" esiste ma è "", .get() ritorna "" non il default
target_base = self.settings.get("target_url", _TARGET_URL).rstrip("/")

# Fix da applicare
target_base = (self.settings.get("target_url") or _TARGET_URL).rstrip("/")
```
Con `settings.json` che ha `"target_url": ""`, sqlmap riceve `-u "/api/login"` — URL invalida, esplode silenziosamente (rc=1, stdout senza "is vulnerable", `findings: []`, `status: "completed"`).

**Bug B — medio: Flask route templates nell'URL**
`/api/store/<int:article_id>/buy` viene passato letteralmente a sqlmap — URL con `<>` → rifiutata. Fix: regex substitution `<int:x>` → `1`, `<path:x>` → `test`, `<x>` → `test` prima di costruire la URL.

**Bug C — minore: path params mai iniettati**
Per endpoint con solo path params (es. `article_id`), né `body_params` né `query_params` matchano → nessun `--data`, nessun marker `*` nella URL → sqlmap non testa il parametro. Fix: sostituire i placeholders Flask con `1*` / `test*` per segnalare il punto di injection.

---

## Stato verifiche e prossimi passi

### Da fare — fix sqlmap (prossima operazione)
1. **`modules/injection/sqlmap_runner.py`**: fix Bug A + Bug B + Bug C
2. **`modules/injection/ghauri_runner.py`**: fix Bug A + Bug B (stessa logica)

### Da verificare su run reale
Tutti i fix delle sessioni 1-2 sono stati testati solo con smoke test sintetici.
Comando di test (richiede servizio Pwnzer0tt1Shop in ascolto):
```bash
./start.py --path=/var/home/gianny/Downloads/Pwnzer0tt1Shop --dev --module=sqlmap
```
Verificare:
- `endpoints_map.json` → `/api/login` ha `params` con `encoding: "json"`
- `sqlmap.json` → finding SQLi su `username`
- `report.md` → sezione sqlmap presente con finding

### Problemi aperti non ancora affrontati

| # | Problema | File | Priorità |
|---|---|---|---|
| 1 | Test end-to-end completo con `--dev` | — | Alta |
| 2 | ghauri: parsing stdout non testato su run reale | `ghauri_runner.py` | Media |
| 3 | `nosql_locations` falsi positivi: `.get(` / `.find(` in TypeScript | `stack_detector.py` | Media |
| 4 | sstimap e commix assenti da `TRIGGERS` → mai schedulati | `orchestrator/trigger_rules.py` | Bassa |
| 5 | `_replace_port_in_service` non testata su formati compose insoliti | `start.py` | Bassa |
| 6 | `--dev` non copre `settings.json` né `assets/` — stessa versione baked nell'immagine | — | Bassa |
