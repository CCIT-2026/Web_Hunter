"""
modules/auth/jwt_tool_runner.py  — gated: uses_jwt AND any(looks_weak)

Testa debolezze JWT con jwt_tool. Si attiva SOLO se stack_detector ha già
rilevato almeno una verifica marcata looks_weak (alg none / verify=False /
weak secret). Se tutti i punti JWT sono robusti, skippa e cita file:riga.

Output: reports/<service>/jwt_tool.json
"""

from modules.base_runner import BaseRunner, make_run_fn

_TARGET_URL = "http://localhost"


class JwtToolRunner(BaseRunner):
    MODULE_NAME = "jwt_tool"

    def execute(self):
        locs = self.stack.get("jwt_verification_locations", [])
        weak = [l for l in locs if l.get("looks_weak")]

        if not self.stack.get("uses_jwt"):
            return "skipped", "skip: uses_jwt=False"

        if not weak:
            # Tutte le verifiche sono robuste: cita la prima come prova
            if locs:
                loc = locs[0]
                return "skipped", f"skip: verifica JWT robusta, vedi {loc['file']}:{loc['line']}"
            return "skipped", "skip: no JWT verification locations found"

        if not self.tool_available("jwt_tool"):
            return "error", "jwt_tool not found in PATH"

        target_base = self.settings.get("target_url", _TARGET_URL).rstrip("/")

        for loc in weak:
            reason = loc.get("weak_reason", "unknown")
            self._test_weakness(target_base, loc, reason)

        return "completed", None

    def _test_weakness(self, target_base: str, loc: dict, reason: str):
        # Find endpoints that use JWT auth
        jwt_endpoints = [ep for ep in self.endpoints if ep.get("auth", {}) and ep["auth"] and "jwt" in ep["auth"].get("type", "")]
        if not jwt_endpoints:
            jwt_endpoints = self.endpoints[:3]  # fallback

        for ep in jwt_endpoints[:5]:
            url = f"{target_base}{ep['path']}"

            if reason == "alg_none":
                # Test: forge token with alg=none
                rc, stdout, _ = self.sh(
                    ["jwt_tool", "PLACEHOLDER_TOKEN", "-X", "a", "-t", url],
                    timeout=self.timeout * 2,
                )
                keyword = "alg:none"
            elif reason == "verify_disabled":
                rc, stdout, _ = self.sh(
                    ["jwt_tool", "PLACEHOLDER_TOKEN", "-X", "n", "-t", url],
                    timeout=self.timeout * 2,
                )
                keyword = "verified"
            else:
                # weak secret: try crack
                rc, stdout, _ = self.sh(
                    ["jwt_tool", "PLACEHOLDER_TOKEN", "-C", "-d",
                     "/home/wordlists/SecLists/Passwords/Common-Credentials/10-million-password-list-top-100.txt",
                     "-t", url],
                    timeout=self.timeout * 4,
                )
                keyword = "cracked"

            for line in stdout.splitlines():
                if keyword in line.lower() or "success" in line.lower():
                    self.add_finding(
                        type_="jwt",
                        file_=loc["file"],
                        line=loc["line"],
                        endpoint=ep["path"],
                        method=ep["method"],
                        confidence="high",
                        detail=f"jwt_tool: {reason} — {line.strip()[:200]}",
                        requires_manual_review=True,
                    )


run = make_run_fn(JwtToolRunner)
