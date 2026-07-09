"""
modules/grpc/grpcurl_runner.py  — gated: has_grpc

Usa grpcurl per:
  1. Listare i servizi (reflection o da .proto file)
  2. Descrivere i metodi di ogni servizio
  3. Bridge verso gli altri moduli: aggiunge gli RPC a endpoints_map.json
     come entry con method="GRPC" per permettere injection testing

Output: reports/<service>/grpcurl.json
"""

import json
from pathlib import Path
from modules.base_runner import BaseRunner, make_run_fn

_DEFAULT_GRPC_ADDR = "localhost:50051"


class GrpcurlRunner(BaseRunner):
    MODULE_NAME = "grpcurl"

    def execute(self):
        if not self.stack.get("has_grpc"):
            return "skipped", "skip: has_grpc=False"
        if not self.tool_available("grpcurl"):
            return "error", "grpcurl not found in PATH"

        addr = self.settings.get("grpc_addr", _DEFAULT_GRPC_ADDR)

        # Try server reflection first
        rc, stdout, _ = self.sh(
            ["grpcurl", "-plaintext", addr, "list"],
            timeout=self.timeout,
        )

        if rc != 0 or not stdout.strip():
            # Fallback: parse from .proto files
            return self._from_proto_files(addr)

        # Parse service list and describe each
        services = [s.strip() for s in stdout.splitlines() if s.strip()]
        for svc in services:
            self._describe_service(addr, svc)

        return "completed", None

    def _describe_service(self, addr: str, svc: str):
        rc, stdout, _ = self.sh(
            ["grpcurl", "-plaintext", addr, "describe", svc],
            timeout=self.timeout,
        )
        if rc != 0:
            return

        # Add each RPC as a pseudo-endpoint for the injection modules
        for line in stdout.splitlines():
            line = line.strip()
            if line.startswith("rpc "):
                # "rpc MethodName ( .pkg.Request ) returns ( .pkg.Response )"
                parts = line.split()
                method_name = parts[1] if len(parts) > 1 else "unknown"
                rpc_path = f"/{svc}/{method_name}"

                self.add_finding(
                    type_="endpoint",
                    file_=None,
                    line=None,
                    endpoint=rpc_path,
                    method="GRPC",
                    confidence="high",
                    detail=f"gRPC RPC {rpc_path} via server reflection",
                )
                # Append to endpoints_map for downstream modules
                self._append_endpoint(rpc_path, svc)

    def _from_proto_files(self, addr: str):
        proto_files = self.stack.get("grpc_proto_files", [])
        if not proto_files:
            return "skipped", "skip: has_grpc=True but no .proto files and no server reflection"

        for proto_rel in proto_files:
            proto_path = self.service_root / proto_rel
            try:
                content = proto_path.read_text(errors="replace")
            except Exception:
                continue
            for i, line in enumerate(content.splitlines()):
                line = line.strip()
                if line.startswith("rpc "):
                    parts = line.split()
                    method_name = parts[1] if len(parts) > 1 else "unknown"
                    self.add_finding(
                        type_="endpoint",
                        file_=proto_rel,
                        line=i + 1,
                        endpoint=f"/grpc/{method_name}",
                        method="GRPC",
                        confidence="medium",
                        detail=f"gRPC RPC from {proto_rel}:{i+1} — no live server for reflection",
                        requires_manual_review=True,
                    )

        return "completed", None

    def _append_endpoint(self, rpc_path: str, service_name: str):
        """Append gRPC endpoint to endpoints_map.json for downstream injection runners."""
        ep_file = self.report_dir / "endpoints_map.json"
        try:
            eps = json.loads(ep_file.read_text()) if ep_file.exists() else []
        except Exception:
            eps = []

        entry = {
            "path": rpc_path,
            "method": "GRPC",
            "file": None,
            "line": None,
            "handler_function": None,
            "params": [],
            "auth": None,
        }
        if not any(e["path"] == rpc_path and e["method"] == "GRPC" for e in eps):
            eps.append(entry)
            ep_file.write_text(json.dumps(eps, indent=2))


run = make_run_fn(GrpcurlRunner)
