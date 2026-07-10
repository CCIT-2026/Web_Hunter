"""
orchestrator/colors.py — output colorato per il pipeline (inside container).

Usato da: core.py, job_queue.py, run_pipeline.py, session_probe.py.
Sempre visibile (print diretto, bypassa il log level di Python logging).
TTY-aware: niente ANSI se stdout non è un terminale (pipe, CI, redirect).
"""

import os
import sys

_tty = sys.stdout.isatty() or os.environ.get("FORCE_COLOR") == "1"

R   = "\033[0m"  if _tty else ""
B   = "\033[1m"  if _tty else ""
DIM = "\033[2m"  if _tty else ""
CY  = "\033[36m" if _tty else ""
GR  = "\033[32m" if _tty else ""
YE  = "\033[33m" if _tty else ""
RE  = "\033[31m" if _tty else ""
MA  = "\033[35m" if _tty else ""


def step(msg: str) -> None:
    print(f"{CY}{B}→{R}  {msg}", flush=True)

def ok(msg: str) -> None:
    print(f"{GR}{B}✓{R}  {msg}", flush=True)

def warn(msg: str) -> None:
    print(f"{YE}{B}⚠{R}  {msg}", flush=True)

def err(msg: str) -> None:
    print(f"{RE}{B}✗{R}  {msg}", file=sys.stderr, flush=True)

def dim(msg: str) -> None:
    print(f"{DIM}{msg}{R}", flush=True)

def header(title: str, width: int = 54) -> None:
    """Separatore di sezione: ─── TITLE ───────────────"""
    bar = "─" * max(0, width - len(title) - 5)
    print(f"\n{CY}{B}─── {title} {bar}{R}", flush=True)
