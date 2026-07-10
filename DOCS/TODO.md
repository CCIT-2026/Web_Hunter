# TODO — Condivisione report con colleghi (git daemon)

## Idea

Permettere ai colleghi di clonare e aggiornare i report in tempo reale via rete locale
(LAN in gara, Tailscale durante il prep) senza bisogno di SSH configurato.

Il protocollo `git://` (porta 9418) è ideale: nessuna autenticazione, zero config lato
client, funziona ovunque ci sia connettività TCP.

## Flusso pensato

1. `start.py` avvia l'analisi e crea il repo git in `reports/<service>/`
2. Prima dell'analisi, richiede consenso e avvia `git daemon` in background
3. Rileva automaticamente l'IP giusto da usare nell'ordine:
   - Interfaccia `player*` o `team*` → VPN CTF tipica
   - Interfaccia `tailscale*` o `ts*` → Tailscale
   - IP di uscita verso 1.1.1.1 → fallback
4. Chiede conferma IP all'utente (con possibilità di correggerlo)
5. Apre la porta 9418 sul firewall locale (firewalld o ufw) chiedendo consenso
6. Stampa i comandi esatti per il collega, sia prima dell'analisi che in fondo
7. A fine analisi, `git commit` automatico dei findings
8. Il collega fa `git clone git://IP/NomeServizio` una volta, poi `git pull` per aggiornamenti

## Problema bloccante

`git daemon` è un subcommand separato non incluso nel pacchetto `git` base su
**Bluefin (Fedora Atomic / immutabile)**. Su queste distro:

- `rpm-ostree install git-daemon` funziona ma richiede reboot
- Homebrew non ha un formula `git-daemon` separato
- Il binario esiste dentro layer di container (toolbox/distrobox) ma non sull'host

Su Ubuntu/Debian standard: `sudo apt install git-daemon-run` — funziona senza reboot.
Su Fedora mutabile: `sudo dnf install git-daemon` — funziona senza reboot.

## Codice già scritto (rimosso temporaneamente)

Tutto il codice è stato scritto e testato parzialmente — rimosso da `start.py` e
`git_sync.py` in attesa di una soluzione cross-distro.

### `git_sync.py` — funzioni da reintegrare

```python
def _find_git() -> str:
    """Cerca git con supporto daemon: PATH → Linuxbrew → fallback."""

def _port_listening(port: int, timeout: float = 3.0) -> bool:
    """Verifica che qualcosa sia davvero in ascolto sulla porta prima di dichiarare successo."""

def start_daemon(reports_base: str, port: int = 9418) -> int | None:
    """
    Avvia git daemon con start_new_session=True (sopravvive alla chiusura di start.py).
    Idempotente via PID file. Verifica porta in ascolto prima di ritornare il PID.
    """
```

### `start.py` — funzioni da reintegrare

```python
def _detect_share_ip() -> tuple[str, str]:
    """Rileva IP VPN (player*/team* → tailscale* → fallback 1.1.1.1)."""

def _open_git_daemon_port(port: int = 9418) -> None:
    """Rileva firewalld/ufw e propone di aprire la porta chiedendo consenso."""
```

E nel `main()`, il blocco tra build immagine e `_run_analysis()`:
- `git_sync.init(report_dir)`
- Detect IP → chiedi conferma → eventuale correzione manuale
- `_open_git_daemon_port()`
- `git_sync.start_daemon(reports_base)`
- Stampa box con `git clone` e `git pull`

E dopo `_run_analysis()`:
- `git_sync.commit(report_dir, f"findings: {service_name}")`
- Ristampa box comandi in fondo (visibile dopo l'output dell'analisi)

## Possibili soluzioni alternative da valutare

- **`git bundle`**: crea un file `.bundle` da condividere manualmente (nessun daemon, ma no live sync)
- **`python3 -m http.server` + `git http-backend`**: richiede configurazione CGI, più complesso
- **Toolbox/Distrobox**: `toolbox run git daemon ...` esponendo la porta all'host — da testare
- **Script wrapper**: script che cerca git-daemon in toolbox se non disponibile sull'host
