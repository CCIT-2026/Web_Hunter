"""
modules/sync/git_sync.py  — sezione 8ter

Gestisce la sincronizzazione Git dei report tra collaboratori via VPN.

Flusso:
  init(report_dir)         — chiama al primo avvio: git init in reports/<service>/
  commit(report_dir, msg)  — chiamato da ogni runner dopo aver scritto il proprio JSON
  clone(url, report_dir)   — se --clone= è passato a start.py: git clone URL report_dir
  pull(report_dir)         — sync incrementale; si ferma su conflitti (no auto-merge)

Nota:
  - Il repo è non-bare, inizializzato dentro la cartella che è già bind-mount → visibile
    dall'host e, se esposta (ssh/git://), clonabile da altri host in VPN.
  - Nessun remote configurato di default: ogni analisi parte con repo locale.
    Il clone/pull viene attivato esplicitamente dall'utente con --clone= o da start.py.
  - In caso di conflitto durante pull, il tool si ferma e stampa istruzioni per
    risoluzione manuale (NO merge automatico di security findings).
"""

import logging
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)

_GIT = ["git"]


def _run(cmd: list[str], cwd: str, check: bool = False) -> tuple[int, str, str]:
    r = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd)
    if check and r.returncode != 0:
        raise RuntimeError(f"git error ({r.returncode}): {r.stderr.strip()}")
    return r.returncode, r.stdout.strip(), r.stderr.strip()


def init(report_dir: str) -> bool:
    """Init git repo inside report_dir (idempotent). Returns True if newly initialized."""
    d = Path(report_dir)
    d.mkdir(parents=True, exist_ok=True)
    git_dir = d / ".git"
    if git_dir.exists():
        return False  # already initialized

    rc, _, err = _run([*_GIT, "init"], cwd=str(d))
    if rc != 0:
        logger.error("git init failed: %s", err)
        return False

    # Initial commit so the repo is cloneable immediately
    (d / ".gitkeep").write_text("")
    _run([*_GIT, "add", ".gitkeep"], cwd=str(d))
    _run([*_GIT, "commit", "-m", "chore: init recon repo"], cwd=str(d))
    logger.info("git: initialized repo in %s", report_dir)
    return True


def commit(report_dir: str, message: str = "chore: update findings") -> bool:
    """Stage all changes in report_dir and commit. Skip if nothing changed."""
    d = str(report_dir)
    rc, status, _ = _run([*_GIT, "status", "--porcelain"], cwd=d)
    if rc != 0 or not status.strip():
        return False  # nothing to commit

    _run([*_GIT, "add", "-A"], cwd=d)
    rc, _, err = _run([*_GIT, "commit", "-m", message, "--allow-empty-message"], cwd=d)
    if rc != 0:
        logger.warning("git commit failed: %s", err)
        return False

    logger.info("git: committed '%s'", message)
    return True


def clone(remote_url: str, report_dir: str) -> bool:
    """Clone a colleague's report repo into report_dir. Fails if dir already exists."""
    d = Path(report_dir)
    if (d / ".git").exists():
        logger.error("Cannot clone: %s already has a git repo. Use pull() instead.", report_dir)
        return False

    d.parent.mkdir(parents=True, exist_ok=True)
    rc, _, err = _run([*_GIT, "clone", remote_url, str(d)], cwd=str(d.parent))
    if rc != 0:
        logger.error("git clone failed: %s", err)
        return False

    logger.info("git: cloned %s → %s", remote_url, report_dir)
    return True


def pull(report_dir: str) -> tuple[bool, str]:
    """
    Fetch + merge from origin. Returns (success, message).
    On conflict: aborts merge and returns (False, conflict_info) — caller shows
    instructions for manual resolution. No auto-merge of security findings.
    """
    d = str(report_dir)

    # Check for a configured remote
    rc, remotes, _ = _run([*_GIT, "remote"], cwd=d)
    if rc != 0 or not remotes.strip():
        return False, "no remote configured — use git_sync.add_remote() or --clone"

    # Fetch
    rc, _, err = _run([*_GIT, "fetch", "--all"], cwd=d)
    if rc != 0:
        return False, f"git fetch failed: {err}"

    # Check for local uncommitted changes
    _, status, _ = _run([*_GIT, "status", "--porcelain"], cwd=d)
    if status.strip():
        return False, "local uncommitted changes detected — commit first with git_sync.commit()"

    # Try merge (fast-forward only preferred, but allow merge commit)
    rc, stdout, err = _run([*_GIT, "merge", "--no-ff", "origin/HEAD", "--no-edit"], cwd=d)
    if rc == 0:
        logger.info("git pull: %s", stdout)
        return True, stdout

    # Conflict: abort and tell the user
    _run([*_GIT, "merge", "--abort"], cwd=d)
    conflict_msg = (
        f"CONFLICT during merge: {err}\n"
        "Risoluzione manuale richiesta:\n"
        f"  cd {report_dir}\n"
        "  git fetch --all\n"
        "  git diff origin/HEAD\n"
        "  # risolvere i conflitti manualmente, poi:\n"
        "  git add -A && git commit -m 'merge: manual conflict resolution'"
    )
    logger.error(conflict_msg)
    return False, conflict_msg


def add_remote(report_dir: str, url: str, name: str = "origin") -> bool:
    d = str(report_dir)
    rc, remotes, _ = _run([*_GIT, "remote"], cwd=d)
    if name in (remotes or "").splitlines():
        _run([*_GIT, "remote", "set-url", name, url], cwd=d)
    else:
        rc, _, err = _run([*_GIT, "remote", "add", name, url], cwd=d)
        if rc != 0:
            logger.error("git remote add failed: %s", err)
            return False
    logger.info("git: remote '%s' → %s", name, url)
    return True
