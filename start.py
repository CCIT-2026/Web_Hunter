#!/usr/bin/env python3
"""
start.py — entrypoint CLI della suite CTF A/D Recon.

Gira sull'HOST (non dentro il container).
Invoca docker/podman per:
  1. Buildare/avviare il container di analisi (con il sorgente del servizio in bind-mount).
  2. Opzionalmente avviare il container del servizio bersaglio (per test dinamici).

Non c'è Docker-in-Docker: è un normale orchestratore host-side che gestisce container
fratelli sulla stessa rete host.

Usage:
  ./start.py                                           # interattivo
  ./start.py --path=/srv/targets/webapp                # non-interattivo
  ./start.py --path=/srv/targets/webapp --module=sqlmap
  ./start.py --path=/srv/targets/webapp --clean        # prune + rimuovi container e immagine
  ./start.py --rebuild                                 # clean + rebuild da zero, poi avvia (chiede il path se manca --path)
  ./start.py --path=/srv/targets/webapp --rebuild      # clean + rebuild + avvia sul servizio dato
  ./start.py --path=/srv/targets/webapp --verbose      # mostra stdout/stderr di tutti i tool
  ./start.py --path=/srv/targets/webapp --debug        # mostra stato variabili, senza stdout tool
  ./start.py --path=/srv/targets/webapp --debug --verbose  # stato variabili + stdout tool
"""

import argparse
import glob
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

_HERE = Path(__file__).parent.resolve()
_SETTINGS_PATH = _HERE / "settings.json"
_DEFAULT_SETTINGS = {
    "webhook_url": "",
    "webhook_port": 18080,
    "webhook_bind": "0.0.0.0",
    "rate_limit_rps": None,
    "timeout_seconds": 15,
    "engine": "docker",
    "wordlists_path": "/home/wordlists",
    "payload_library_path": "/assets/payloads_all_the_things.json",
    "payload_library_max_per_endpoint": 3,
    "max_workers": 4,
    "target_url": "",
    "grpc_addr": "localhost:50051",
    "test_user": {
        "username":   "ctf_probe",
        "password":   "Probe1234!",
        "email":      "probe@ctf.local",
        "phone":      "0000000000",
        "first_name": "CTF",
        "last_name":  "Probe",
        "name":       "CTF Probe",
    },
}
_IMAGE_NAME = "ctf-recon-suite:latest"

# Ports almost certainly belonging to infrastructure, not the web frontend.
# Used to filter compose port mappings and post-compose port-diff results.
_SYSTEM_PORTS: set[int] = {
    20, 21, 22, 23, 25, 53, 80, 110, 143, 389, 443, 445, 993, 995,
    1433,          # MSSQL
    3306,          # MySQL / MariaDB
    5432,          # PostgreSQL
    6379,          # Redis
    9200, 9300,    # Elasticsearch
    27017, 27018,  # MongoDB
    5672, 15672,   # RabbitMQ AMQP + management UI
    1883, 8883,    # MQTT
    9092,          # Kafka
    2181,          # Zookeeper
    11211,         # Memcached
    5601,          # Kibana
    4369,          # Erlang EPMD
    50051,         # gRPC default
}


# ---------------------------------------------------------------------------
# Output — colored step messages always shown; tool output gated by flags
#
# Comportamento flag:
#   (nessuno)         → solo messaggi colorati, stdout tool soppressi
#   --verbose         → messaggi colorati + stdout/stderr di tutti i tool
#   --debug           → messaggi colorati + dump variabili compatto, NO stdout tool
#   --debug --verbose → messaggi colorati + dump variabili + stdout tool
# ---------------------------------------------------------------------------

# Pre-parse flags: argparse non è ancora disponibile, ma ci servono subito
_verbose = "--verbose" in sys.argv
_debug   = "--debug"   in sys.argv


class _C:
    """ANSI codes — disabilitati se stdout non è un TTY (pipe, CI, redirect)."""
    _tty    = sys.stdout.isatty()
    RESET   = "\033[0m"  if _tty else ""
    BOLD    = "\033[1m"  if _tty else ""
    DIM     = "\033[2m"  if _tty else ""
    CYAN    = "\033[36m" if _tty else ""
    GREEN   = "\033[32m" if _tty else ""
    YELLOW  = "\033[33m" if _tty else ""
    RED     = "\033[31m" if _tty else ""
    MAGENTA = "\033[35m" if _tty else ""


def step(msg: str) -> None:
    print(f"{_C.CYAN}{_C.BOLD}→{_C.RESET}  {msg}", flush=True)

def ok(msg: str) -> None:
    print(f"{_C.GREEN}{_C.BOLD}✓{_C.RESET}  {msg}", flush=True)

def warn(msg: str) -> None:
    print(f"{_C.YELLOW}{_C.BOLD}⚠{_C.RESET}  {msg}", flush=True)

def err(msg: str) -> None:
    print(f"{_C.RED}{_C.BOLD}✗{_C.RESET}  {msg}", file=sys.stderr, flush=True)

def section(title: str) -> None:
    """Intestazione di sezione — separa visivamente i blocchi del flusso."""
    w = 54
    bar = "╌" * max(0, w - len(title) - 4)
    print(f"\n{_C.CYAN}{_C.BOLD}╌╌ {title} {bar}{_C.RESET}", flush=True)

def dbg(**kwargs) -> None:
    """Dump compatto variabili — solo con --debug."""
    if not _debug:
        return
    parts = "  ".join(
        f"{_C.MAGENTA}{k}{_C.RESET}={_C.DIM}{repr(v)}{_C.RESET}"
        for k, v in kwargs.items()
    )
    print(f"{_C.DIM}[dbg]{_C.RESET} {parts}")


def run_cmd(cmd: list, *, cwd: str | None = None, shell: bool = False, capture: bool = False):
    """
    Esegue un sottoprocesso rispettando --verbose / --debug.

    capture=False (default)
        Sopprime stdout/stderr per default.
        Con --verbose li lascia fluire sul terminale.
    capture=True
        Cattura sempre stdout/stderr per uso logico (returncode, parsing).
        Con --verbose li stampa anche sul terminale dopo la cattura.

    Con --debug logga il comando lanciato — mai l'output del tool.
    Ritorna sempre CompletedProcess (returncode sempre disponibile).
    """
    if _debug:
        label = cmd if shell else " ".join(str(c) for c in cmd)
        print(f"{_C.DIM}[dbg]{_C.RESET} {_C.MAGENTA}$>{_C.RESET} {label}")

    if capture:
        r = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd, shell=shell)
        if _verbose:
            if r.stdout.strip():
                sys.stdout.write(r.stdout)
            if r.stderr.strip():
                sys.stderr.write(r.stderr)
        return r
    else:
        if _verbose:
            return subprocess.run(cmd, cwd=cwd, shell=shell)
        return subprocess.run(cmd, capture_output=True, cwd=cwd, shell=shell)


def run_interactive(cmd, *, cwd: str | None = None, shell: bool = False):
    """Comandi approvati dall'utente: output sempre visibile indipendentemente dai flag."""
    if _debug:
        label = cmd if shell else " ".join(str(c) for c in cmd)
        print(f"{_C.DIM}[dbg]{_C.RESET} {_C.MAGENTA}$>{_C.RESET} {label}")
    return subprocess.run(cmd, cwd=cwd, shell=shell)


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------

def load_settings() -> dict:
    if not _SETTINGS_PATH.exists():
        _SETTINGS_PATH.write_text(json.dumps(_DEFAULT_SETTINGS, indent=2))
        ok(f"Creato {_SETTINGS_PATH} con valori di default")
    with open(_SETTINGS_PATH) as f:
        saved = json.load(f)
    return {**_DEFAULT_SETTINGS, **saved}


# ---------------------------------------------------------------------------
# Container helpers
# ---------------------------------------------------------------------------

def _engine_cmd(engine: str) -> str:
    return engine  # "docker" or "podman" — same CLI syntax


def _container_name(service_path: str) -> str:
    h = hashlib.md5(str(Path(service_path).resolve()).encode()).hexdigest()[:8]
    slug = Path(service_path).name.replace(" ", "_").lower()
    return f"ctf-recon-{slug}-{h}"


# ---------------------------------------------------------------------------
# Per-service URL cache
#
# target_url is stored per-service (keyed by MD5 of resolved path) inside
# settings["services"], so switching between services never reuses a stale URL.
# The top-level settings["target_url"] is kept for backwards compatibility.
# ---------------------------------------------------------------------------

def _service_key(service_path: str) -> str:
    return hashlib.md5(str(Path(service_path).resolve()).encode()).hexdigest()[:12]


def _get_service_url(settings: dict, service_path: str) -> "str | None":
    return settings.get("services", {}).get(_service_key(service_path), {}).get("target_url")


def _save_service_url(settings: dict, service_path: str, url: str) -> None:
    key = _service_key(service_path)
    settings.setdefault("services", {})[key] = {
        "target_url": url,
        "name": Path(service_path).name,
    }
    settings["target_url"] = url  # backwards compat for container env var
    _SETTINGS_PATH.write_text(json.dumps(settings, indent=2))


def _clean(engine: str):
    """Rimuove SOLO i container ctf-recon-* e l'immagine ctf-recon-suite:latest."""
    step("Pulizia container e immagine recon...")
    dbg(engine=engine, image=_IMAGE_NAME)

    r = run_cmd([engine, "ps", "-aq", "--filter", "name=ctf-recon-"], capture=True)
    ids = [i for i in r.stdout.strip().splitlines() if i]
    if ids:
        step(f"Rimozione {len(ids)} container recon...")
        run_cmd([engine, "rm", "-f"] + ids)
        ok(f"{len(ids)} container rimossi.")
    else:
        ok("Nessun container recon attivo.")

    r = run_cmd([engine, "rmi", "-f", _IMAGE_NAME], capture=True)
    if r.returncode == 0:
        ok(f"Immagine {_IMAGE_NAME} rimossa.")
    else:
        warn(f"Immagine {_IMAGE_NAME} non trovata o già rimossa.")

    ok("Clean completato.")


def _image_exists(engine: str) -> bool:
    r = subprocess.run(
        [engine, "image", "inspect", _IMAGE_NAME],
        capture_output=True,
    )
    return r.returncode == 0


def _build_image(engine: str, no_cache: bool = False):
    dockerfile = _HERE / "Dockerfile"
    if not dockerfile.exists():
        err(f"Dockerfile non trovato: {dockerfile}")
        sys.exit(1)
    cmd = [engine, "build", "-t", _IMAGE_NAME, str(_HERE)]
    if no_cache:
        cmd.insert(2, "--no-cache")

    dbg(dockerfile=str(dockerfile), no_cache=no_cache, image=_IMAGE_NAME)
    step(f"Build immagine {_IMAGE_NAME}{'  (--no-cache)' if no_cache else ''}  (può richiedere alcuni minuti)...")

    # Always stream build output — never suppress: failures must be visible.
    r = subprocess.run(cmd)
    if r.returncode != 0:
        err("Build immagine fallita.")
        sys.exit(1)
    ok("Immagine costruita.")


def _run_analysis(
    engine: str,
    service_path: str,
    service_name: str,
    report_dir: str,
    settings: dict,
    module: str | None = None,
    verbose: bool = False,
    debug: bool = False,
    dev: bool = False,
):
    """Launch or re-use the analysis container."""
    container = _container_name(service_path)

    # Serialize settings to pass as env var (the container reads it)
    settings_json = json.dumps(settings)

    cmd = [
        engine, "run",
        "--rm",
        "--name", container,
        "--network", "host",  # share host network: service containers reachable at localhost
        # Mounts — :z relabela il contesto SELinux per l'uso in container (necessario su Fedora/RHEL)
        "-v", f"{service_path}:/service:ro,z",
        "-v", f"{report_dir}:/reports/{service_name}:rw,z",
        # Settings + runtime params
        "-e", f"RECON_SETTINGS={settings_json}",
        "-e", f"SERVICE_NAME={service_name}",
        "-e", f"SERVICE_ROOT=/service",
        "-e", f"REPORT_DIR=/reports/{service_name}",
    ]
    if dev:
        cmd += ["-v", f"{_HERE}/modules:/app/modules:ro,z"]
        cmd += ["-v", f"{_HERE}/orchestrator:/app/orchestrator:ro,z"]
    if module:
        cmd += ["-e", f"SINGLE_MODULE={module}"]
    if verbose:
        cmd += ["-e", "VERBOSE=1"]
    if debug:
        cmd += ["-e", "DEBUG=1"]
    if sys.stdout.isatty():
        cmd += ["-e", "FORCE_COLOR=1"]

    cmd += [_IMAGE_NAME]

    dbg(
        container=container,
        service_name=service_name,
        module=module or "(tutti)",
        target_url=settings.get("target_url") or "(non impostato)",
        dev=dev,
    )
    step(f"Avvio analisi  {service_name}{'  [' + module + ']' if module else ''}...")

    run_interactive(cmd)


# ---------------------------------------------------------------------------
# Target service — port detection utilities
# ---------------------------------------------------------------------------

_BURP_RESERVED = {8080}


def _is_port_busy(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.3)
        return s.connect_ex((host, port)) == 0


def _find_free_ports(exclude: set[int], count: int = 3) -> list[int]:
    found, p = [], 1024
    while len(found) < count and p < 65535:
        if p not in exclude and not _is_port_busy("127.0.0.1", p):
            found.append(p)
        p += 1
    return found


def _detect_compose_file(service_path: str) -> "Path | None":
    root = Path(service_path)
    subdirs = [root] + [d for d in root.iterdir() if d.is_dir() and not d.name.startswith(".")]
    for name in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"):
        for base in subdirs:
            p = base / name
            if p.exists():
                return p
    return None


def _parse_web_ports(compose_file: "Path | None") -> list[int]:
    """
    Extract candidate web-frontend ports from a compose file (or Dockerfiles),
    filtering out known infrastructure/DB ports from _SYSTEM_PORTS.

    Returns an ordered list — earlier entries are more likely to be the frontend.
    """
    candidates: list[int] = []
    seen: set[int] = set()

    def _add(port: int) -> None:
        if port not in seen and port not in _SYSTEM_PORTS and 1024 <= port <= 65534:
            seen.add(port)
            candidates.append(port)

    if compose_file:
        text = compose_file.read_text(errors="replace")
        # Match all host-side port mappings: "HOST:CONTAINER" or "IP:HOST:CONTAINER"
        for m in re.finditer(
            r'["\']?(?:\d{1,3}(?:\.\d{1,3}){3}:)?(\d{2,5}):\d{2,5}',
            text,
        ):
            try:
                _add(int(m.group(1)))
            except ValueError:
                pass

    # Fallback: EXPOSE directives in any Dockerfile under the same root
    if not candidates and compose_file:
        for df in compose_file.parent.rglob("Dockerfile*"):
            for m in re.finditer(r"^EXPOSE\s+(\d+)", df.read_text(errors="replace"), re.M):
                try:
                    _add(int(m.group(1)))
                except ValueError:
                    pass

    return candidates


def _listening_ports() -> set[int]:
    """Return the set of TCP ports currently in LISTEN state (uses `ss`)."""
    try:
        r = subprocess.run(
            ["ss", "-tlnH"], capture_output=True, text=True, timeout=3
        )
        ports: set[int] = set()
        for line in r.stdout.splitlines():
            # ss -tlnH columns: State Recv-Q Send-Q Local-Addr:Port Peer-Addr:Port
            for part in line.split():
                if ":" in part:
                    port_str = part.rsplit(":", 1)[1]
                    if port_str.isdigit():
                        ports.add(int(port_str))
        return ports
    except Exception:
        return set()


def _startup_timeout(compose_file: "Path | None") -> int:
    """Estimate startup timeout based on heavy dependencies declared in compose."""
    if compose_file is None:
        return 20
    text = compose_file.read_text(errors="replace").lower()
    heavy = ("postgres", "mysql", "mariadb", "mongodb", "redis", "kafka", "elasticsearch")
    return 45 if any(kw in text for kw in heavy) else 20


def _replace_port_in_service(
    service_path: str,
    old_host: str, old_port: int,
    new_host: str, new_port: int,
) -> list[str]:
    """Aggiorna host:port in tutti i file rilevanti del servizio (compose, Dockerfile, client, env)."""
    root = Path(service_path)
    _SKIP = {".git", "node_modules", "__pycache__", "venv", ".venv", "dist", "build"}
    _TEXT_EXT = {".yml", ".yaml", ".py", ".js", ".ts", ".jsx", ".tsx",
                 ".rb", ".go", ".env", ".conf", ".toml", ".ini"}
    changed = []

    def _sub(text: str, f: Path) -> str:
        t = text
        if f.suffix in {".yml", ".yaml"} or "Dockerfile" in f.name:
            t = re.sub(
                rf'(["\']?)(?:{re.escape(old_host)}:)?{old_port}:(\d+)',
                rf'\g<1>{new_host}:{new_port}:\g<2>',
                t,
            )
        for alias in (old_host, "localhost"):
            t = t.replace(f"{alias}:{old_port}", f"{new_host}:{new_port}")
        return t

    for f in root.rglob("*"):
        if not f.is_file() or any(s in f.parts for s in _SKIP):
            continue
        if f.suffix not in _TEXT_EXT and not re.search(r"Dockerfile|docker-compose|client\b|\.env", f.name):
            continue
        try:
            original = f.read_text(errors="replace")
            updated = _sub(original, f)
            if updated != original:
                f.write_text(updated)
                changed.append(str(f.relative_to(root)))
        except Exception:
            pass
    return changed


def _is_privileged_port(port: int, engine: str) -> bool:
    """True se la porta non può essere bindata da podman rootless."""
    if engine != "podman" or port >= 1024:
        return False
    try:
        r = subprocess.run(
            ["sysctl", "-n", "net.ipv4.ip_unprivileged_port_start"],
            capture_output=True, text=True,
        )
        return port < int(r.stdout.strip())
    except Exception:
        return port < 1024


def _wait_for_service(url: str, timeout: int = 20) -> bool:
    print(f"{_C.CYAN}{_C.BOLD}→{_C.RESET}  Attendo HTTP su {url}", end="", flush=True)
    for _ in range(timeout):
        try:
            urllib.request.urlopen(url, timeout=1)
            print(f"  {_C.GREEN}OK{_C.RESET}")
            return True
        except Exception:
            print(".", end="", flush=True)
            time.sleep(1)
    print(f"  {_C.YELLOW}timeout{_C.RESET}")
    return False


# ---------------------------------------------------------------------------
# _resolve_target_url — cascade port detection (service-agnostic)
# ---------------------------------------------------------------------------

def _resolve_target_url(
    engine: str,
    service_path: str,
    compose_file: "Path | None",
    settings: dict,
) -> str:
    """
    Determine the target URL for this specific service using a 6-step cascade:

    1. Per-service URL cache (keyed by path hash) — instant if already known
    2. Parse compose/Dockerfile → filter _SYSTEM_PORTS → candidate list
    3. Privileged port remapping for podman rootless (before compose up)
    4. compose up -d  +  port-diff scan (ss snapshot before vs after)
    5. Wait for first candidate to accept TCP (dynamic timeout for DB deps)
    6. Ask user with detected suggestions

    The detected URL is saved to the per-service cache so future runs are instant.
    """
    host = "127.0.0.1"

    # --- 1. Per-service URL cache ---
    cached = _get_service_url(settings, service_path)
    if cached:
        try:
            _h, _p = cached.rstrip("/").rsplit(":", 1)
            _h = _h.replace("http://", "").replace("https://", "")
            if _is_port_busy(_h, int(_p)):
                ok(f"URL in cache: {cached}")
                return cached
        except Exception:
            pass
        warn(f"Cache ({cached}) non raggiungibile — rilevo porta...")

    # --- 2. Parse candidate web ports from compose ---
    compose_candidates = _parse_web_ports(compose_file)
    if compose_candidates:
        step(f"Porte candidate dal compose (filtrate system ports): {compose_candidates}")
    else:
        step("Nessuna porta web trovata nel compose — uso solo port-diff scan")

    # --- 3. Privileged port remapping (podman rootless, before compose up) ---
    for i, port in enumerate(compose_candidates):
        if _is_privileged_port(port, engine):
            excl = _BURP_RESERVED | set(compose_candidates)
            free = _find_free_ports(exclude=excl)
            new_port = free[0] if free else port + 8000
            warn(f"Porta {port} privilegiata (podman rootless) — rimappo a {new_port}")
            changed = _replace_port_in_service(service_path, host, port, host, new_port)
            if changed:
                ok(f"File aggiornati: {', '.join(changed)}")
            compose_candidates[i] = new_port

    # --- 4. Port-diff scan + compose up ---

    # Pre-check: if a candidate is already accepting connections, skip compose up entirely.
    # This covers: service already started manually in pre-commands, or a previous run left it up.
    for port in compose_candidates:
        if _is_port_busy(host, port):
            url = f"http://{host}:{port}"
            ok(f"Servizio già in ascolto su porta {port}  →  {url}")
            _save_service_url(settings, service_path, url)
            return url

    ports_before = _listening_ports()

    if compose_file:
        section("Avvio servizio target")
        step(f"{engine} compose up -d")
        # Use a hard timeout so that compose providers that don't properly detach
        # (e.g. podman-compose on rootless podman) don't block the tool indefinitely.
        try:
            r = subprocess.run(
                [engine, "compose", "up", "-d"],
                cwd=str(compose_file.parent),
                timeout=30,
            )
            if r.returncode != 0:
                err("Avvio compose fallito — continuo comunque con port scan.")
        except subprocess.TimeoutExpired:
            warn("compose up non ha risposto in 30s — continuo (i container potrebbero essere già up).")
        step("Attendo stabilizzazione porte (2s)...")
        time.sleep(2)

    step("Scan porte in ascolto...")
    ports_after = _listening_ports()
    diff_ports = sorted((ports_after - ports_before) - _SYSTEM_PORTS - {0, 65535})
    if diff_ports:
        step(f"Nuove porte rilevate post-compose: {diff_ports}")
    else:
        step(f"Nessuna nuova porta nel diff — uso candidati da compose: {compose_candidates}")

    # Merge: compose-parsed candidates first (more reliable label), then diff-detected
    all_candidates = list(dict.fromkeys(compose_candidates + diff_ports))

    # --- 5. Wait for first reachable candidate (dynamic timeout) ---
    # Quick pass: maybe it's already up
    for port in all_candidates:
        if _is_port_busy(host, port):
            url = f"http://{host}:{port}"
            ok(f"Porta attiva: {port}  →  {url}")
            _save_service_url(settings, service_path, url)
            return url

    timeout = _startup_timeout(compose_file)
    if all_candidates:
        step(f"Attendo avvio (max {timeout}s)  candidati: {all_candidates}")
        for _ in range(timeout):
            for port in all_candidates:
                if _is_port_busy(host, port):
                    url = f"http://{host}:{port}"
                    ok(f"Porta attiva: {port}  →  {url}")
                    _save_service_url(settings, service_path, url)
                    return url
            print(".", end="", flush=True)
            time.sleep(1)
        print()
        warn(f"Nessun candidato ha risposto in {timeout}s.")

    # --- 6. Ask user ---
    suggestion = str(all_candidates[0]) if all_candidates else "5000"
    hint = f"  (rilevate: {', '.join(map(str, all_candidates))})" if all_candidates else ""
    warn(f"Porta non rilevata automaticamente.{hint}")
    try:
        port = int(_ask("Inserisci porta manualmente", suggestion))
    except ValueError:
        port = int(suggestion)
    url = f"http://{host}:{port}"
    _save_service_url(settings, service_path, url)
    return url


# ---------------------------------------------------------------------------
# Pre-launch commands
# ---------------------------------------------------------------------------

def _run_precommands(service_path: str) -> None:
    """Chiede comandi da eseguire prima dell'avvio del servizio."""
    section("Comandi pre-avvio")
    step("$ ls -la")
    run_interactive("ls -la --color=always", shell=True, cwd=service_path)
    print(f"  {_C.DIM}Inserisci comandi da eseguire ora (vuoto o 'n' per terminare){_C.RESET}")
    print(f"  {_C.DIM}Nota: il compose up verrà avviato automaticamente dopo.{_C.RESET}")
    while True:
        cmd = _ask("Comando").strip()
        if not cmd or cmd.lower() in ("n", "no"):
            break
        step(f"$ {cmd}")
        run_interactive(cmd, shell=True, cwd=service_path)


# ---------------------------------------------------------------------------
# Interactive mode
# ---------------------------------------------------------------------------

def _ask(prompt: str, default: str = "") -> str:
    hint = f"  {_C.DIM}[{default}]{_C.RESET}" if default else ""
    val = input(f"  {_C.CYAN}{_C.BOLD}{prompt}{_C.RESET}{hint}  {_C.BOLD}›{_C.RESET}  ").strip()
    return val or default

def _ask_yn(prompt: str, default: str = "s") -> bool:
    opts = f"{_C.DIM}[{default}]{_C.RESET}"
    val = input(f"  {_C.CYAN}{_C.BOLD}{prompt}{_C.RESET}  {opts}  {_C.BOLD}›{_C.RESET}  ").strip().lower()
    val = val or default.lower()
    return val in ("s", "si", "sì", "y", "yes")

def _show_tree(service_path: str) -> None:
    root = Path(service_path)
    entries = sorted(
        (e.name + ("/" if e.is_dir() else "") for e in root.iterdir() if not e.name.startswith(".")),
        key=lambda x: (not x.endswith("/"), x),
    )
    for i, e in enumerate(entries):
        prefix = "└──" if i == len(entries) - 1 else "├──"
        print(f"  {_C.DIM}{prefix}{_C.RESET}  {e}")


def _pick_path_fzf(prompt: str) -> "str | None":
    """Seleziona una directory con fzf. Ritorna None se fzf non è disponibile o l'utente annulla."""
    if not shutil.which("fzf"):
        return None
    try:
        # find gira in background e alimenta fzf mentre scansiona
        find = subprocess.Popen(
            ["find", str(Path.home()), "-maxdepth", "6", "-type", "d",
             "-not", "-path", "*/\\.*"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
        )
        result = subprocess.run(
            [
                "fzf",
                "--prompt",         f"  {prompt}  ›  ",
                "--preview",        "ls --color=always {}",
                "--preview-window", "right:50%:border-left",
                "--height",         "70%",
                "--border",         "rounded",
                "--info",           "inline",
                "--header",         "INVIO: conferma   ESC/CTRL-C: digita manualmente",
            ],
            stdin=find.stdout,
            capture_output=True, text=True,
        )
        find.terminate()
        chosen = result.stdout.strip()
        return chosen if result.returncode == 0 and chosen else None
    except Exception:
        return None


def _enable_path_autocomplete() -> None:
    """Abilita tab-completion per path filesystem su readline."""
    try:
        import readline

        def _completer(text: str, state: int) -> "str | None":
            pattern = os.path.expanduser(text) + "*"
            matches = [
                m + ("/" if os.path.isdir(m) else "")
                for m in glob.glob(pattern)
            ]
            return matches[state] if state < len(matches) else None

        readline.set_completer(_completer)
        readline.set_completer_delims(" \t\n")
        readline.parse_and_bind("tab: complete")
    except ImportError:
        pass


def interactive_mode(settings: dict) -> tuple[str, str, str]:
    section("Configurazione servizio")
    chosen = _pick_path_fzf("Path sorgente servizio")
    if chosen:
        ok(f"Selezionato: {chosen}")
        service_path = str(Path(chosen).resolve())
    else:
        if not shutil.which("fzf"):
            warn("fzf non trovato — usa TAB per l'autocomplete del path")
        _enable_path_autocomplete()
        raw = _ask("Path sorgente  (TAB per completare)")
        if not raw:
            err("Path obbligatorio.")
            sys.exit(1)
        service_path = str(Path(raw).expanduser().resolve())

    service_name = _ask("Nome servizio", Path(service_path).name)
    report_dir   = _ask("Output report",  str(_HERE / "reports" / service_name))
    return service_path, service_name, report_dir


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="CTF A/D Recon Suite")
    parser.add_argument("--path",      help="Path al sorgente del servizio")
    parser.add_argument("--module",    help="Esegui solo questo modulo (es. --module=sqlmap)")
    parser.add_argument("--clean",     action="store_true", help="Rimuovi container recon e pruna il sistema")
    parser.add_argument("--rebuild",   action="store_true", help="Clean + rebuild immagine da zero")
    parser.add_argument("--dev",       action="store_true", help="Monta modules/ locale (test senza rebuild)")
    parser.add_argument("--no-target", action="store_true", help="Salta l'avvio interattivo del servizio target")
    parser.add_argument("--verbose",   action="store_true", help="Mostra stdout/stderr di tutti i tool")
    parser.add_argument("--debug",     action="store_true", help="Mostra stato variabili (senza stdout tool)")
    args = parser.parse_args()

    settings = load_settings()

    # Engine viene letto esclusivamente da settings.json (campo "engine")
    engine = settings.get("engine", "docker")

    if args.clean:
        _clean(engine)
        return

    if args.path:
        # Non-interactive
        service_path = str(Path(args.path).resolve())
        service_name = Path(service_path).name
        report_dir = str(_HERE / "reports" / service_name)
    else:
        # Interactive
        service_path, service_name, report_dir = interactive_mode(settings)

    dbg(
        engine=engine,
        service_path=service_path,
        service_name=service_name,
        report_dir=report_dir,
        module=args.module or "(tutti)",
        dev=args.dev,
        rebuild=args.rebuild,
        no_target=args.no_target,
    )

    Path(report_dir).mkdir(parents=True, exist_ok=True)

    # --- Target service startup ---
    if not args.no_target:
        _show_tree(service_path)
        _run_precommands(service_path)
        compose_file = _detect_compose_file(service_path)
        target_url = _resolve_target_url(engine, service_path, compose_file, settings)
        # HTTP-level readiness check (TCP already passed inside _resolve_target_url)
        _wait_for_service(target_url, timeout=_startup_timeout(compose_file))

    # --- Build & run analysis ---
    section("Build immagine")
    if args.rebuild:
        _clean(engine)
        _build_image(engine, no_cache=True)
    elif _image_exists(engine):
        ok(f"Immagine {_IMAGE_NAME} già presente — skip build.  (usa --rebuild per forzare)")
    else:
        _build_image(engine)

    _run_analysis(
        engine=engine,
        service_path=service_path,
        service_name=service_name,
        report_dir=report_dir,
        settings=settings,
        module=args.module,
        verbose=args.verbose,
        debug=args.debug,
        dev=args.dev,
    )

    section("Completato")
    ok(f"Quick report   →  {report_dir}/quick_report.md")
    ok(f"Report esteso  →  {report_dir}/extended_report.md")
    ok(f"JSON  →  {report_dir}/json_reports/  (include stats.json e semgrep_raw.json)")


if __name__ == "__main__":
    try:
        print((_HERE / "assets" / ".logo" / "ascii_art.txt").read_text())
    except OSError:
        pass

    main()
