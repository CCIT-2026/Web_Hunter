"""
modules/payload_library/loader.py

Carica e indicizza payloads_all_the_things.json una volta sola (singleton).
Il JSON ha 629 oggetti: {category, section, subsection, language, payload}.

Mapping categorie PayloadsAllTheThings → chiavi interne usate da trigger_rules.py:
  "SQL Injection"            → sqli
  "NoSQL Injection"          → nosql
  "Server Side Template Injection" → ssti
  "Command Injection"        → command_injection
  "Server Side Request Forgery"    → ssrf
  "GraphQL Injection"        → graphql
  "XPath Injection"          → xpath
  "Directory Traversal"      → directory_traversal
  "LDAP Injection"           → ldap
  "JWT"                      → jwt
  "XML External Entity"      → xxe
  ecc.  (vedi CATEGORY_ALIASES sotto per il mapping completo)
"""

import json
import logging
from collections import defaultdict
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_DEFAULT_PATH = "/assets/payloads_all_the_things.json"

CATEGORY_ALIASES: dict[str, str] = {
    # canonical PayloadsAllTheThings → internal key
    "sql injection":                        "sqli",
    "nosql injection":                      "nosql",
    "server side template injection":       "ssti",
    "server-side template injection":       "ssti",
    "command injection":                    "command_injection",
    "os command injection":                 "command_injection",
    "server side request forgery":          "ssrf",
    "ssrf":                                 "ssrf",
    "graphql injection":                    "graphql",
    "xpath injection":                      "xpath",
    "directory traversal":                  "directory_traversal",
    "path traversal":                       "directory_traversal",
    "ldap injection":                       "ldap",
    "jwt":                                  "jwt",
    "json web token":                       "jwt",
    "xml external entity":                  "xxe",
    "xxe injection":                        "xxe",
    "cross-site scripting":                 "xss",
    "xss":                                  "xss",
    "open redirect":                        "open_redirect",
    "file inclusion":                       "file_inclusion",
    "local file inclusion":                 "file_inclusion",
    "remote file inclusion":                "file_inclusion",
    "insecure deserialization":             "deserialization",
    "php object injection":                 "deserialization",
    "crlf injection":                       "crlf",
    "http response splitting":              "crlf",
    "type juggling":                        "type_juggling",
    "race condition":                       "race_condition",
    "api key leaks":                        "secret",
    "account takeover":                     "auth",
    "cors misconfiguration":                "cors",
    "clickjacking":                         "clickjacking",
    "csv injection":                        "csv_injection",
    "formula injection":                    "csv_injection",
    "css injection":                        "css_injection",
    "dom clobbering":                       "xss",
    "dns rebinding":                        "ssrf",
}


class PayloadLibrary:
    """Singleton: caricato al primo accesso, poi mantenuto in memoria."""

    _instance: "PayloadLibrary | None" = None

    def __new__(cls, path: str | None = None):
        if cls._instance is None:
            obj = super().__new__(cls)
            obj._loaded = False
            cls._instance = obj
        return cls._instance

    def load(self, path: str | None = None) -> "PayloadLibrary":
        if self._loaded:
            return self
        p = Path(path or _DEFAULT_PATH)
        if not p.exists():
            logger.warning("payloads file not found at %s — library empty", p)
            self._index: dict[str, list[dict]] = {}
            self._raw: list[dict] = []
            self._loaded = True
            return self

        self._raw = json.loads(p.read_text())
        self._index = defaultdict(list)
        for item in self._raw:
            # Index by both the original category and the internal alias
            cat_orig = item.get("category", "").strip().lower()
            self._index[cat_orig].append(item)
            alias = CATEGORY_ALIASES.get(cat_orig)
            if alias and alias != cat_orig:
                self._index[alias].append(item)

        logger.info("PayloadLibrary: loaded %d payloads across %d categories", len(self._raw), len(self._index))
        self._loaded = True
        return self

    def get_by_category(self, category: str) -> list[dict]:
        """Restituisce tutti i payload per una categoria (case-insensitive, alias inclusi)."""
        if not self._loaded:
            self.load()
        key = category.strip().lower()
        # Try direct match, then alias lookup
        result = self._index.get(key, [])
        if not result:
            alias = CATEGORY_ALIASES.get(key)
            if alias:
                result = self._index.get(alias, [])
        return result

    def all_categories(self) -> list[str]:
        if not self._loaded:
            self.load()
        return sorted(self._index.keys())


def get_library(path: str | None = None) -> PayloadLibrary:
    return PayloadLibrary().load(path)
