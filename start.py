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
  ./start.py                              # interattivo
  ./start.py --path=/srv/targets/webapp   # non-interattivo
  ./start.py --path=/srv/targets/webapp --module=sqlmap
  ./start.py --path=/srv/targets/webapp --clone=git@10.0.0.2:reports/webapp
  ./start.py --path=/srv/targets/webapp --clean        # prune + rimuovi container e immagine
"""

import argparse
import hashlib
import json
import os
import subprocess
import sys
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
}
_IMAGE_NAME = "ctf-recon-suite:latest"


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------

def load_settings() -> dict:
    if not _SETTINGS_PATH.exists():
        _SETTINGS_PATH.write_text(json.dumps(_DEFAULT_SETTINGS, indent=2))
        print(f"[init] Created {_SETTINGS_PATH} with defaults")
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


def _clean(engine: str):
    """Rimuove SOLO i container e l'immagine di Web Hunter, poi pruning limitato.

    Cosa tocca:
      - Container il cui nome inizia con ctf-recon-  (tutti i servizi analizzati)
      - Immagine ctf-recon-suite:latest
      - Layer intermedi dangling (untagged) rimasti dai build → image prune -f
        Questi sono strati senza tag lasciati da rebuild precedenti; non toccano
        immagini con tag, volumi o container di altri progetti.

    Cosa NON tocca:
      - Qualsiasi altro container, immagine o volume sul sistema.
      - 'system prune' e '--volumes' sono intenzionalmente assenti.
    """
    # 1. Ferma e rimuove tutti i container ctf-recon-* (filter per nome, non globale)
    result = subprocess.run(
        [engine, "ps", "-aq", "--filter", "name=ctf-recon-"],
        capture_output=True, text=True,
    )
    ids = [i for i in result.stdout.strip().splitlines() if i]
    if ids:
        print(f"[clean] Removing {len(ids)} recon container(s)…")
        subprocess.run([engine, "rm", "-f"] + ids)
    else:
        print("[clean] No recon containers found.")

    # 2. Rimuove solo l'immagine ctf-recon-suite:latest
    r = subprocess.run([engine, "rmi", "-f", _IMAGE_NAME], capture_output=True, text=True)
    if r.returncode == 0:
        print(f"[clean] Image {_IMAGE_NAME} removed.")
    else:
        print(f"[clean] Image {_IMAGE_NAME} not found or already removed.")

    # 3. Pruning limitato: solo layer dangling (untagged) rimasti dai nostri build.
    #    'image prune -f' rimuove SOLO immagini senza tag — non tocca nient'altro.
    #    NON usiamo 'system prune' né '--volumes': quello sarebbe globale e distruttivo.
    print("[clean] Pruning dangling build layers (untagged images only)…")
    subprocess.run([engine, "image", "prune", "-f"])
    print("[clean] Done.")


def _build_image(engine: str):
    dockerfile = _HERE / "Dockerfile"
    if not dockerfile.exists():
        print(f"[error] Dockerfile not found at {dockerfile}", file=sys.stderr)
        sys.exit(1)
    cmd = [engine, "build", "-t", _IMAGE_NAME, str(_HERE)]
    print(f"[build] {' '.join(cmd)}")
    r = subprocess.run(cmd)
    if r.returncode != 0:
        print("[error] Image build failed", file=sys.stderr)
        sys.exit(1)


def _run_analysis(
    engine: str,
    service_path: str,
    service_name: str,
    report_dir: str,
    settings: dict,
    module: str | None = None,
    verbose: bool = False,
    debug: bool = False,
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
    if module:
        cmd += ["-e", f"SINGLE_MODULE={module}"]
    if verbose:
        cmd += ["-e", "VERBOSE=1"]
    if debug:
        cmd += ["-e", "DEBUG=1"]

    cmd += [_IMAGE_NAME]
    print(f"[run] {' '.join(cmd)}")
    subprocess.run(cmd)


def _clone_reports(engine: str, clone_url: str, report_dir: str, service_name: str):
    """Clone a colleague's report repo instead of starting fresh."""
    from modules.sync import git_sync
    print(f"[sync] Cloning {clone_url} → {report_dir}")
    ok = git_sync.clone(clone_url, report_dir)
    if not ok:
        print("[error] Clone failed — check URL and VPN connectivity", file=sys.stderr)
        sys.exit(1)
    print(f"[sync] Clone OK. Reports available in {report_dir}")
    # Pull latest if already cloned
    ok2, msg = git_sync.pull(report_dir)
    print(f"[sync] Pull: {msg}")


# ---------------------------------------------------------------------------
# Interactive mode
# ---------------------------------------------------------------------------

def _ask(prompt: str, default: str = "") -> str:
    val = input(f"{prompt} [{default}]: ").strip()
    return val or default


def interactive_mode(settings: dict) -> tuple[str, str | None, str | None]:
    service_path = _ask("Service source path")
    if not service_path:
        print("[error] Service path required", file=sys.stderr)
        sys.exit(1)
    service_path = str(Path(service_path).resolve())

    service_name = _ask("Service name", Path(service_path).name)
    report_dir = _ask("Report output dir", str(_HERE / "reports" / service_name))

    existing = Path(report_dir) / "detected_stack.json"
    clone_url = None
    if not existing.exists():
        choice = _ask("New analysis or sync with colleague? (new/sync)", "new")
        if choice.strip().lower() == "sync":
            clone_url = _ask("Git URL of colleague's report repo")

    return service_path, service_name, report_dir, clone_url


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Web Hunter - A/D Recon Suite")
    parser.add_argument("--path", help="Path to service source")
    parser.add_argument("--module", help="Run only this module (e.g. --module=sqlmap)")
    parser.add_argument("--clone", metavar="GIT_URL", help="Clone colleague's report repo")
    parser.add_argument("--clean", action="store_true", help="Remove recon containers and prune the container system")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--debug", action="store_true")
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
        clone_url = args.clone
    else:
        # Interactive
        service_path, service_name, report_dir, clone_url = interactive_mode(settings)
        if args.clone:
            clone_url = args.clone

    Path(report_dir).mkdir(parents=True, exist_ok=True)

    if clone_url:
        _clone_reports(engine, clone_url, report_dir, service_name)
        return

    # Ensure image is built
    _build_image(engine)

    # Init git repo in report_dir for incremental sync
    sys.path.insert(0, str(_HERE))
    try:
        from modules.sync import git_sync
        git_sync.init(report_dir)
    except ImportError:
        pass  # git_sync optional

    _run_analysis(
        engine=engine,
        service_path=service_path,
        service_name=service_name,
        report_dir=report_dir,
        settings=settings,
        module=args.module,
        verbose=args.verbose,
        debug=args.debug,
    )

    print(f"\n[done] Report: {report_dir}/report.md")


if __name__ == "__main__":
    with open('assets/.logo/ascii_art.txt') as logo:
        logo_ascii = logo.read()
        print(logo_ascii)

    main()
