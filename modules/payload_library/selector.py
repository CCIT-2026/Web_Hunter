"""
modules/payload_library/selector.py

Interfaccia pubblica della payload library per i runner.
Esporta get_candidates() usata da tutti i moduli che testano payload.

Regole (dalla spec):
  - max_results di default basso (da settings, default 3)
  - ogni tentativo va giustificato da un endpoint/parametro concreto dal mapping
  - filtro per language (es. no PowerShell su target Linux/bash)
  - se nessun payload plausibile, ritorna lista vuota — il caller decide se skippare

Nessun invio massivo: è compito del caller limitare ulteriormente
(es. 1-2 richieste per endpoint, non N payload × M endpoint).
"""

import logging
import random
from typing import Any

from modules.payload_library.loader import get_library

logger = logging.getLogger(__name__)

_DEFAULT_MAX = 3

# Linguaggi da escludere per target (heuristic: se non è Windows, salta powershell)
_EXCLUDE_FOR_NON_WINDOWS = {"powershell", "windows", "cmd.exe", ".bat", ".ps1"}
_EXCLUDE_FOR_NON_PHP = {"php", "<?php", "phpinfo"}
_EXCLUDE_FOR_NON_JAVA = {".class", "java.lang", "Runtime.exec"}


def get_candidates(
    category: str,
    context: dict | None = None,
    language: str | None = None,
    max_results: int = _DEFAULT_MAX,
    exclude_language: str | None = None,
    library_path: str | None = None,
) -> list[dict]:
    """
    Restituisce al massimo max_results payload per la categoria richiesta.

    Args:
        category:        Chiave interna o categoria PayloadsAllTheThings.
        context:         Dizionario opzionale con info extra (non usato ora, espandibile).
        language:        Linguaggio del payload desiderato (filtra per .language nel JSON).
        max_results:     Cap sul numero di risultati.
        exclude_language: Pattern da escludere (case-insensitive substring su .language o .payload).
        library_path:    Override del path del JSON (utile in test).
    """
    lib = get_library(library_path)
    candidates = lib.get_by_category(category)

    if not candidates:
        logger.debug("get_candidates: no payloads for category=%r", category)
        return []

    # Language filter (inclusion)
    if language:
        lang_lower = language.lower()
        filtered = [p for p in candidates if not p.get("language") or p["language"].lower() == lang_lower]
        if filtered:
            candidates = filtered  # only narrow if we got hits

    # Language exclusion (e.g. no powershell on linux targets)
    if exclude_language:
        excl = exclude_language.lower()
        candidates = [
            p for p in candidates
            if not _payload_matches_exclusion(p, excl)
        ]

    # Shuffle to avoid always returning the first N entries (bias)
    shuffled = list(candidates)
    random.shuffle(shuffled)

    result = shuffled[:max_results]
    logger.debug("get_candidates: category=%r → %d/%d payloads selected", category, len(result), len(candidates))
    return result


def _payload_matches_exclusion(item: dict, excl: str) -> bool:
    lang = (item.get("language") or "").lower()
    payload = (item.get("payload") or "").lower()
    return excl in lang or excl in payload


def get_candidates_for_stack(
    category: str,
    stack: dict,
    settings: dict,
    library_path: str | None = None,
) -> list[dict]:
    """
    Versione convenience usata dai runner che hanno già stack e settings.
    Deduce automaticamente language e max_results.
    """
    lang = stack.get("language", "")
    max_n = int(settings.get("payload_library_max_per_endpoint", _DEFAULT_MAX))

    # Heuristic: exclude platform-specific payloads for Linux targets
    exclude = None
    if lang in ("python", "javascript", "php", "ruby", "go"):
        exclude = "powershell"

    return get_candidates(
        category=category,
        language=None,  # language filter on payload language is too restrictive for most categories
        max_results=max_n,
        exclude_language=exclude,
        library_path=library_path,
    )
