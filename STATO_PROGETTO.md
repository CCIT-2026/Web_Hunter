# CTF A/D Recon Suite — Stato del progetto

## Come funziona attualmente

### Architettura generale

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

Il codice dei moduli è **baked nell'immagine** al momento del build. Per testare modifiche senza rebuild usare `--dev`.

---

### Flusso di esecuzione di start.py

1. Legge `settings.json` (engine, timeout, target_url, ecc.)
2. **Avvio target** (se `target_url` non è già impostato e non si passa `--no-target`):
   - Mostra i file nella cartella del servizio
   - Chiede se avviare con `docker/podman compose up -d`
   - Se no: chiede comandi da runnare prima, poi richiede
   - Gestione conflitto porta: prova prima `127.0.0.2:stessa-porta`; se anche quella è occupata, propone 3 porte libere (mai 8080) e modifica i file del servizio
   - Attende che il servizio risponda su HTTP
   - Salva `target_url` in `settings.json`
3. Build immagine (con cache; `--rebuild` fa clean + `--no-cache`)
4. `docker/podman run` con i mount e le env var necessarie
5. Dentro il container: `mapping → stack_detector → moduli → report.md`

---

### Flag di start.py

| Flag | Comportamento |
|---|---|
| `--path=PATH` | Path del servizio da analizzare (altrimenti chiede) |
| `--module=NAME` | Runna solo quel modulo (es. `--module=semgrep`) |
| `--rebuild` | Clean completo + build `--no-cache` prima di avviare |
| `--dev` | Monta `./modules/` e `./orchestrator/` sopra l'immagine — testa modifiche **senza rebuild** |
| `--no-target` | Salta l'avvio interattivo del servizio target |
| `--clean` | Rimuove container e immagine ctf-recon-*, prune dangling layers |
| `--clone=URL` | Clona il repo report di un collega invece di partire da zero |

---

### Moduli e output

| Modulo | Tipo | Richiede servizio attivo? | Output |
|---|---|---|---|
| semgrep | statico | No | `semgrep.json` |
| ripgrep | statico | No | `ripgrep.json` |
| sqlmap | dinamico | **Sì** | `sqlmap.json` |
| ghauri | dinamico | **Sì** | `ghauri.json` |
| nuclei | dinamico | **Sì** | `nuclei.json` |
| jsluice | statico | No | `jsluice.json` |
| trufflehog / gitleaks | statico | No | `*.json` |
| … | … | … | … |

I moduli dinamici leggono `settings["target_url"]` e ci costruiscono le URL degli endpoint rilevati da `mapping`.

---

## Modifiche apportate in questa sessione

### `modules/discovery/semgrep_runner.py`

**Problema:** i numeri di riga nel report erano sbagliati.

**Cronologia tentativi:**
1. `_true_line()` — rimappava `start.line` ipotizzando che semgrep contasse solo righe non-vuote. Sbagliato: produceva numeri ancora più errati (es. 94 → 118).
2. `_locate_snippet()` — cercava il testo del finding (`extra.lines`) nel file reale. Inutile: senza login Semgrep cloud `extra.lines = "requires login"`.
3. **`_line_from_offset()` — soluzione corretta.** Il campo `start.offset` nel JSON di semgrep è il byte offset dall'inizio del file, sempre presente, non richiede login. `text[:offset].count("\n") + 1` dà la riga esatta.

```python
# semgrep_runner.py:79-80
offset = start.get("offset")
line_no = _line_from_offset(self.service_root / rel_path, offset) if offset is not None else start.get("line")
```

**Stato:** implementato, **non ancora verificato** (richiede rebuild o `--dev`).

---

### `orchestrator/core.py`

**Problema:** con `--module=NAME` il report.md non veniva generato.

**Causa:** `_run_single()` eseguiva il modulo e ritornava senza chiamare `_generate_markdown_report()`. Quest'ultima era chiamata solo nella pipeline completa (Phase 3).

**Fix:** aggiunta chiamata a `_generate_markdown_report()` alla fine di `_run_single()`.

**Stato:** implementato, **non ancora verificato**.

---

### `start.py`

**Aggiunti:**
- `--rebuild`: `_clean()` + `_build_image(no_cache=True)` prima dell'analisi
- `--dev`: monta `./modules/` e `./orchestrator/` nel container a runtime — zero rebuild durante lo sviluppo
- `--no-target`: salta il launcher del servizio target
- `_start_target_service()`: launcher interattivo completo (vedi flusso sopra)
- `_replace_port_in_service()`: sostituisce host:porta in compose, Dockerfile e file client
- `_detect_compose_file()`, `_detect_service_port()`, `_find_free_ports()`, `_is_port_busy()`, `_wait_for_service()`

---

## Problemi aperti

### 1. Numeri di riga semgrep — non verificati
`_line_from_offset` è la soluzione giusta concettualmente, ma non è ancora stata testata su un run reale. Verificare con:
```bash
./start.py --path=/var/home/gianny/Downloads/Pwnzer0tt1Shop --module=semgrep --dev
```
e confrontare le righe in `reports/Pwnzer0tt1Shop/report.md` con il file `backend/app.py`.

### 2. report.md con `--module` — non verificato
Il fix in `core.py` è presente ma non testato. Stesso comando sopra verifica entrambe le cose.

### 3. sqlmap e ghauri — output vuoto
Causa confermata: nessun servizio target in ascolto. Il launcher interattivo è ora implementato in `start.py`, ma non è ancora stato testato end-to-end. Testare con:
```bash
./start.py --path=/var/home/gianny/Downloads/Pwnzer0tt1Shop --module=sqlmap
```
(seguire il flusso interattivo per avviare Pwnzer0tt1Shop).

### 4. `_replace_port_in_service` — edge case non testati
La regex per i binding compose (`"PORT:PORT"` → `"NEW_HOST:NEW_PORT:PORT"`) è scritta ma non testata su formati insoliti (es. range di porte, binding su socket Unix).

### 5. `--dev` non copre tutti i file modificati
`--dev` monta `modules/` e `orchestrator/`, ma NON `settings.json` né `assets/`. Se si modifica `settings.json` sull'host, il container vede la versione baked nell'immagine. Per ora workaround: passare le impostazioni come env var o fare rebuild.
