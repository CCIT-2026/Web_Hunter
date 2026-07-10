# Web Hunter — Review del codice & bug residui

> **Data:** 2026-07-10 · **Scope:** intero progetto (orchestrator, modules, start.py, Dockerfile, tests)
> **Metodo:** import di tutti i 36 moduli, run end-to-end della pipeline su `tests/fixtures/flask_sqli`
> (senza Docker), esecuzione della suite `pytest`, revisione mirata dei runner modificati di recente
> (dalfox, smuggler, proxy_config) e dei file core.

## Esito generale

**La suite è in buono stato e funzionante.** Tutti i moduli si importano senza errori, la pipeline
gira end-to-end (Fase 1 → 1.5 → 2 → 3), il gating dichiarativo è coerente, la gestione errori è
robusta (tool mancanti → errore pulito, nessun crash) e i fix sqlmap/ghauri documentati nello STATO
(fallback `target_url`, sanitizzazione dei path Flask, body JSON) risultano **applicati**.

I punti sotto sono gli **unici** che consiglio di correggere. Sono tutti piccoli e localizzati:
nessuno richiede rifattorizzazioni. Ordine per impatto.

---

## 🔴 Da correggere

### 1. Falso positivo NoSQL su qualsiasi `.get(` / `.set(`  — *report accuracy + trigger spurio*

**File:** `orchestrator/stack_detector.py:57`

```python
NOSQL_REDIS = re.compile(r"""redis\.(?:get|set|hget|hset|lpush|rpush|zadd)|\.get\(|\.set\(""")
```

Le alternative finali `\.get\(` e `\.set\(` sono **non ancorate** e matchano qualunque chiamata
`.get(` / `.set(`: `request.json.get(...)`, `dict.get(...)`, `headers.get(...)`, `app.get('/route')`,
`os.environ.get(...)`. Di fatto **ogni** servizio Python/JS viene marcato `has_nosql: true`.

**Impatto verificato** — sulla fixture `flask_sqli` (puro SQLite, zero NoSQL) il report mostra
`NoSQL: ✅` e `nosql_locations` punta a righe come `request.json.get("username")`. Oltre a sporcare
ogni report, su un servizio con `.get(` ma **senza** SQL rilevato (es. ORM non riconosciuto) il
trigger `has_nosql AND NOT has_sql_queries` fa partire `nosqli` a vuoto. È il problema noto #3 dello
STATO.

**Fix (minimale):** togliere le due alternative generiche; la detection Mongo/Redis reale resta.

```python
NOSQL_REDIS = re.compile(r"""redis\.(?:get|set|hget|hset|lpush|rpush|zadd)""")
```

> Nota: `_detect_nosql` usa `NOSQL_REDIS` sia come gate a livello di file sia come matcher di riga.
> Rimuovendo `\.get\(|\.set\(`, i servizi realmente Mongo continuano a passare via `NOSQL_MONGO`
> e `NOSQL_FIND`; i Redis puri via `redis.get/set`. Un Redis usato con nomi di variabile diversi da
> `redis.` non verrà rilevato, ma è un falso negativo raro e molto preferibile all'attuale rumore.

---

### 2. `start.py` crasha se lanciato da una directory diversa dalla root  — *launch failure*

**File:** `start.py:745`

```python
if __name__ == "__main__":
    with open('assets/.logo/ascii_art.txt') as logo:   # path RELATIVO
        print(logo.read())
    main()
```

Tutto il resto di `start.py` usa `_HERE` (path assoluto risolto da `__file__`), ma il logo apre un
path **relativo alla cwd**. Lanciando `/percorso/Web_Hunter/start.py` da un'altra directory:

```
FileNotFoundError: [Errno 2] No such file or directory: 'assets/.logo/ascii_art.txt'
```

**Verificato** eseguendo `start.py --help` da `/tmp`. Il crash avviene *prima* di `main()`, quindi
anche `--help` fallisce.

**Fix:** usare il path assoluto già disponibile, e non far dipendere l'avvio dal logo.

```python
if __name__ == "__main__":
    logo_path = _HERE / "assets" / ".logo" / "ascii_art.txt"
    try:
        print(logo_path.read_text())
    except OSError:
        pass
    main()
```

---

### 3. `yaml.load(..., Loader=yaml.SafeLoader)` marcato come pericoloso  — *falso positivo SAST*

**File:** `orchestrator/stack_detector.py:69`

```python
YAML_LOAD = re.compile(r"""yaml\.load\s*\((?!\s*[^,)]+Loader\s*=\s*yaml\.(?:Safe|Base|Full)Loader)""")
```

Il lookahead negativo usa `[^,)]+`, che **non può attraversare la virgola**: quando il `Loader=` è
il secondo argomento (`yaml.load(stream, Loader=yaml.SafeLoader)`) il lookahead fallisce e la load
sicura viene comunque flaggata → `has_eval_on_input` falso positivo. È il caso coperto dal test
`test_eval_on_input`, attualmente rosso.

**Fix:** consentire al lookahead di superare la virgola (`[^,)]` → `[^)]`).

```python
YAML_LOAD = re.compile(r"""yaml\.load\s*\((?!\s*[^)]+Loader\s*=\s*yaml\.(?:Safe|Base|Full)Loader)""")
```

---

## 🟡 Minori (opzionali — non bloccano il funzionamento)

| # | File | Problema | Nota |
|---|---|---|---|
| 4 | `modules/lang_specific/smuggler_runner.py:39` | `rc == -1` (tool-not-found in `BaseRunner.sh`) viene etichettato `"timeout"`; il timeout reale è `rc == -2`. Inoltre manca il pre-check `tool_available("smuggler")` presente negli altri runner. | Solo messaggio fuorviante; nessun crash. |
| 5 | `Dockerfile:120-122` | Il blocco `RUN … smuggler` è **dopo** `ENTRYPOINT` (funziona — `ENTRYPOINT` non termina il build — ma è anomalo) e il symlink non fa `chmod +x` (dipende dal bit eseguibile preservato da git). | Spostare il blocco prima di `WORKDIR/ENTRYPOINT` per chiarezza. |
| 6 | vari (`base_runner.py`, `stack_detector.py`, `markdown_report.py`…) | `datetime.datetime.utcnow()` è deprecato e verrà rimosso in una futura Python. | Sostituire con `datetime.now(datetime.UTC)`. Non urgente (il container usa una Python compatibile). |
| 7 | `state_history/STATO_PROGETTO.md` vs `start.py` | Lo STATO documenta il flag `--clone=URL`, ma non è definito nell'`argparse` di `start.py` (verrebbe rifiutato). Il modulo `modules/sync/git_sync.py` esiste ma non è cablato nella CLI. | Doc drift: rimuovere `--clone` dalla doc **oppure** aggiungerlo all'argparse. |

---

## Stato della suite di test (`pytest tests/`)

**39 passati, 3 skippati, 5 falliti.** I 5 fallimenti si classificano così:

| Test | Categoria | Causa |
|---|---|---|
| `test_stack_detector::test_eval_on_input` | **bug reale** | Regex YAML → vedi punto **#3** |
| `test_stack_detector::test_detect_go_grpc_fixture` | **gap di copertura** | `_detect_ssrf` copre solo `.py`/`.js`; non rileva la SSRF Go (`http.Get(url)`). Il test si aspetta `has_outbound_request_on_input: true`. Aggiungere un pattern Go **oppure** marcare il test `xfail`. |
| `test_trigger_rules::test_empty_stack_no_module_triggered` | **test stale** | Scelta di design: `sqlmap`/`ghauri`/`dalfox` ora sono `lambda s: True` (sempre attivi su endpoint parametrizzati), documentata nel commento di `trigger_rules.py`. Il test va aggiornato per whitelistare gli always-on. |
| `test_trigger_rules::test_missing_stack_key_fails_closed` | **test stale** | Stessa causa: gli always-on non "falliscono chiusi". |
| `test_orchestrator::test_markdown_report_generated` | **test stale** | Il test scrive gli artefatti nella root di `tmp_path`, ma `markdown_report.generate()` (e tutta la pipeline) ora legge da `json_reports/`. Il test va aggiornato per scrivere in `tmp_path/json_reports/`. |

**In sintesi:** solo **1** fallimento su 5 è un bug del codice (#3); **3** sono test da riallineare a
scelte già prese e **1** è un gap di copertura opzionale. Aggiornare i 3 test stale e correggere il
punto #3 porta la suite completamente verde (il gap Go resta una scelta).

---

## Verifiche eseguite (evidenza)

- **Import di tutti i 36 moduli del registry:** 36/36 OK, `run()` presente dove atteso.
- **`compileall` su `modules/ orchestrator/ start.py`:** nessun errore di sintassi.
- **Run end-to-end** (`orchestrator.run_pipeline` su `tests/fixtures/flask_sqli`, senza Docker):
  pipeline completata, 11 moduli "completati"/errore-pulito, 16 saltati per gating, 0 crash;
  `detected_stack.json`, `endpoints_map.json`, `extended_report.md`, `quick_report.md`, `stats.json`
  generati e coerenti (a parte il falso positivo NoSQL del punto #1).
