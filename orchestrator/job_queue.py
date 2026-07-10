"""
orchestrator/job_queue.py

Job queue con concorrenza esplicita (non ThreadPoolExecutor di default):
  - Semaforo globale sul numero di job paralleli (da settings.max_workers)
  - Mutex groups: insiemi di moduli che non possono girare contemporaneamente
    (es. due tool che colpiscono lo stesso endpoint, o che scrivono lo stesso file)
  - Rate limiting opzionale (token bucket), disattivato di default

Interfaccia:
  queue = JobQueue(settings, mutex_groups=MUTEX_GROUPS)
  queue.submit(name, fn, *args, **kwargs)
  queue.join()                      # blocca finché tutti i job sono finiti
  results = queue.results           # dict {name: return_value | Exception}
"""

import logging
import threading
import time
from collections import defaultdict
from typing import Any, Callable

logger = logging.getLogger(__name__)

# Moduli che non devono girare contemporaneamente: stesso gruppo = mutex
# Il valore è il nome del lock condiviso; moduli in gruppi diversi si ignorano.
# Nota: la chiave non è il "nome del lock" ma un label di gruppo che può
# raggruppare N moduli. Ogni gruppo usa un threading.Lock() dedicato.
DEFAULT_MUTEX_GROUPS: dict[str, str] = {
    # Due tool SQLi sullo stesso endpoint contemporaneamente causano falsi positivi
    "sqlmap":  "sqli_group",
    "ghauri":  "sqli_group",
    # Upload tester non devono sovrascriversi i file di test
    "slipit":   "upload_group",
    "exiftool": "upload_group",
    "polyglot": "upload_group",
    # Reports dir (writing the same detected_stack.json during init)
    "mapping":        "init_group",
    "stack_detector": "init_group",
}


class _TokenBucket:
    """Thread-safe token bucket per rate limiting (RPS)."""

    def __init__(self, rate: float):
        self._rate = rate       # tokens / second
        self._tokens = rate
        self._last = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self):
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last
            self._tokens = min(self._rate, self._tokens + elapsed * self._rate)
            self._last = now
            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return
        # Not enough tokens: sleep until next token
        sleep_time = (1.0 - self._tokens) / self._rate
        time.sleep(sleep_time)
        self._tokens = 0.0


class JobQueue:
    def __init__(self, settings: dict, mutex_groups: dict[str, str] | None = None):
        max_workers = int(settings.get("max_workers", 4))
        rate_rps = settings.get("rate_limit_rps")  # None = disabled

        self._semaphore = threading.Semaphore(max_workers)
        self._bucket = _TokenBucket(rate_rps) if rate_rps else None
        self._mutex_groups = mutex_groups or DEFAULT_MUTEX_GROUPS

        # One lock per mutex group label
        self._group_locks: dict[str, threading.Lock] = defaultdict(threading.Lock)

        self._threads: list[threading.Thread] = []
        self._results: dict[str, Any] = {}
        self._results_lock = threading.Lock()

    # -----------------------------------------------------------------------

    def submit(self, name: str, fn: Callable, *args, **kwargs):
        """Accoda e avvia il job in background (thread)."""
        t = threading.Thread(
            target=self._run_job,
            args=(name, fn, args, kwargs),
            name=f"job-{name}",
            daemon=True,
        )
        self._threads.append(t)
        t.start()

    def join(self):
        """Blocca finché tutti i job sono terminati."""
        for t in self._threads:
            t.join()

    @property
    def results(self) -> dict[str, Any]:
        return dict(self._results)

    # -----------------------------------------------------------------------
    # Internal
    # -----------------------------------------------------------------------

    def _run_job(self, name: str, fn: Callable, args: tuple, kwargs: dict):
        group_name = self._mutex_groups.get(name)
        group_lock = self._group_locks[group_name] if group_name else None

        # 1. Rate limit (global, optional)
        if self._bucket:
            self._bucket.acquire()

        # 2. Global concurrency semaphore
        self._semaphore.acquire()
        try:
            # 3. Mutex group lock (se appartiene a un gruppo)
            if group_lock:
                group_lock.acquire()
            try:
                from orchestrator.colors import B, R, DIM, CY, GR, YE, RE
                print(f"{CY}{B}→{R}  {name:<22} avvio...", flush=True)
                t0 = time.monotonic()
                result = fn(*args, **kwargs)
                elapsed = time.monotonic() - t0
                n = len(result.get("findings", [])) if isinstance(result, dict) else 0
                status = result.get("status", "?") if isinstance(result, dict) else "?"
                findings_tag = f"  {B}[{n} finding{'s' if n != 1 else ''}]{R}" if n else ""
                if status == "skipped":
                    print(f"  {DIM}↷  {name:<22} saltato{R}", flush=True)
                elif status == "error":
                    reason = result.get("skip_reason", "") if isinstance(result, dict) else ""
                    print(f"  {RE}{B}✗{R}  {name:<22} errore  ({elapsed:.1f}s)  {DIM}{reason}{R}", flush=True)
                else:
                    print(f"  {GR}{B}✓{R}  {name:<22} {elapsed:.1f}s{findings_tag}", flush=True)
            except Exception as exc:
                result = exc
                print(f"  {RE}{B}✗{R}  {name:<22} CRASH: {exc}", flush=True)
                logger.exception("[queue] ERROR  %s: %s", name, exc)
            finally:
                if group_lock:
                    group_lock.release()
        finally:
            self._semaphore.release()

        with self._results_lock:
            self._results[name] = result
