"""
modules/lang_specific/proxy_config_runner.py  — gated: has_proxy_configs

Analizza staticamente i file di configurazione del proxy (Nginx/Apache) 
presenti nel sorgente e segnala debolezze comuni.

Vulnerabilità rilevate:
- Nginx Alias Traversal (es. location /static { alias /app/static/; })
- Esposizione di cartelle o file sensibili (.git, backup, /server-status)
- Direttive di sicurezza mancanti o errate (es. proxy_pass su indirizzi vulnerabili)
"""

import re
from pathlib import Path
from modules.base_runner import BaseRunner, make_run_fn

# Cerca location /xyz { alias /abc/; } (senza slash finale su location ma presente su alias)
# Per semplicita usiamo una multi-line per Nginx
_NGINX_ALIAS_TRAVERSAL = re.compile(
    r"""location\s+([^\s{]+)(?<!/)\s*\{[^}]*alias\s+([^;]+)/;""", re.I | re.S
)

# Cerca locazioni che espongono direttamente cartelle sensibili
_EXPOSED_SENSITIVE = re.compile(
    r"""location\s+~?\*?\s*['"]?/\.(git|env|ds_store|svn|hg|bzr|htaccess|htpasswd)\b""", re.I
)

# Cerca direttive proxy_pass a localhost o servizi noti
_PROXY_PASS_LOCALHOST = re.compile(
    r"""proxy_pass\s+https?://(?:127\.0\.0\.1|localhost)(?::\d+)?(?:/|;|\s)""", re.I
)

class ProxyConfigRunner(BaseRunner):
    MODULE_NAME = "proxy_config"

    def execute(self):
        if not self.stack.get("has_proxy_configs"):
            return "skipped", "skip: has_proxy_configs=False"

        for fpath in self.service_root.rglob("*"):
            if ".git" in fpath.parts or fpath.is_dir():
                continue
            name_lower = fpath.name.lower()
            if not (name_lower in ("nginx.conf", "apache2.conf", "httpd.conf", ".htaccess") or name_lower.endswith(".conf")):
                continue

            rel = str(fpath.relative_to(self.service_root))
            try:
                src = fpath.read_text(errors="replace")
            except Exception:
                continue

            lines = src.splitlines()

            # Analisi per blocchi (utile per regex multiline)
            for m_alias in _NGINX_ALIAS_TRAVERSAL.finditer(src):
                loc_path, alias_path = m_alias.group(1), m_alias.group(2)
                # Calcola approssimativamente la linea per il report
                line_no = src[:m_alias.start()].count("\n") + 1
                self.add_finding(
                    type_="misconfig",
                    file_=rel, line=line_no,
                    endpoint=None, method=None,
                    confidence="high",
                    detail=(
                        f"Nginx Alias Traversal in location '{loc_path}' linking to alias '{alias_path}/'. "
                        f"Permette la lettura di file fuori dalla directory indicata tramite '../../' traversal."
                    ),
                )

            # Analisi riga per riga per Nginx
            for i, line in enumerate(lines):
                # 2. Check Esposizione file sensibili
                if _EXPOSED_SENSITIVE.search(line):
                    self.add_finding(
                        type_="misconfig",
                        file_=rel, line=i + 1,
                        endpoint=None, method=None,
                        confidence="high",
                        detail="Exposing sensitive directories/files (e.g. .git, .env) in proxy configuration location rule.",
                    )

                # 3. Check proxy_pass verso localhost (utile per identificare SSRF o bypass interni)
                if _PROXY_PASS_LOCALHOST.search(line):
                    self.add_finding(
                        type_="info",
                        file_=rel, line=i + 1,
                        endpoint=None, method=None,
                        confidence="low",
                        detail="Proxy forwarding to localhost (proxy_pass) detected. Check for SSRF-to-RCE target pivots.",
                    )

        return "completed", None

run = make_run_fn(ProxyConfigRunner)
