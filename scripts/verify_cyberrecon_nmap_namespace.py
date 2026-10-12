#!/usr/bin/env python3
"""Owned Nmap qualification in a NEW user/network namespace; no host port scan."""
import argparse
import json
import os
import re
from pathlib import Path
import subprocess
import sys
import threading
import socketserver
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = Path(__file__).resolve().parents[1]


def isolated(parent, current, uid):
    return (uid == 0 and isinstance(parent, str) and isinstance(current, str)
            and re.fullmatch(r"net:\[\d+\]", parent) is not None
            and re.fullmatch(r"net:\[\d+\]", current) is not None and parent != current)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--inside", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--parent-netns", help=argparse.SUPPRESS)
    args = parser.parse_args()
    output = Path(args.output).resolve()
    if not args.inside:
        output.mkdir(parents=True, exist_ok=False)
        command = ["unshare", "--user", "--map-root-user", "--net", sys.executable,
                   str(Path(__file__).resolve()), "--inside", "--output", str(output),
                   "--parent-netns", os.readlink("/proc/self/ns/net")]
        with (output / "namespace.log").open("w") as stream:
            result = subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT, timeout=500)
        (output / "namespace.exit").write_text(str(result.returncode) + "\n")
        print(json.dumps({"command": command, "exit": result.returncode,
                          "scope": "new user/network namespace, process-owned loopback only"}))
        return result.returncode

    parent = args.parent_netns
    current = os.readlink("/proc/self/ns/net")
    uid_map = Path("/proc/self/uid_map").read_text().split()
    if not isolated(parent, current, os.geteuid()) or len(uid_map) != 3 or uid_map[0] != "0" or uid_map[2] != "1":
        parser.error("Refusing Nmap qualification without a distinct parent network namespace and namespace root.")
    command = ["ip", "link", "set", "lo", "up"]
    subprocess.run(command, check=True, timeout=10)
    sys.path.insert(0, str(ROOT))
    from cyberrecon.engines import port_scan, ToolError
    from cyberrecon.scope import Scope

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            try:
                self.wfile.write(b"Owned isolated Nmap lab")
            except (BrokenPipeError, ConnectionResetError):
                pass
        def handle(self):
            try:
                super().handle()
            except (BrokenPipeError, ConnectionResetError):
                pass
        def log_message(self, *args):
            pass

    class UDPHandler(socketserver.BaseRequestHandler):
        def handle(self):
            self.request[1].sendto(b"Owned namespace UDP fixture", self.client_address)

    udp_server = socketserver.ThreadingUDPServer(("127.0.0.1", 0), UDPHandler)
    udp_thread = threading.Thread(target=udp_server.serve_forever, daemon=True)
    udp_thread.start()
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    report = {"status": "RUNNING", "parent_netns": parent, "lab_netns": current,
              "namespace_uid": os.geteuid(), "uid_map": uid_map, "host_privileges": "not elevated",
              "scope": ["127.0.0.1"], "listener_port": server.server_port,
              "setup_command": command, "checks": {}, "production": "NOT APPROVED / BLOCKED"}
    report_path = output / "verification.json"

    def save():
        report_path.write_text(json.dumps(report, indent=2))

    def qualify(name, **options):
        diagnostics = []
        parsed, raw = port_scan("127.0.0.1", Scope(["127.0.0.1"]), diagnostic=diagnostics.append, **options)
        (output / (name + ".xml")).write_bytes(raw)
        (output / (name + ".json")).write_text(json.dumps(parsed, indent=2))
        (output / (name + "-commands.json")).write_text(json.dumps(diagnostics, indent=2))
        assert diagnostics and all(d["returncode"] == 0 for d in diagnostics)
        report["checks"][name] = {"status": "PASS", "profile": parsed["profile"],
                                  "partial": parsed["partial"], "coverage": parsed.get("coverage", []),
                                  "commands": diagnostics}
        save()
        return parsed

    try:
        save()
        full = qualify("full-tcp", profile="full", rate=1000, timeout=300, host_timeout=300)
        assert full["partial"] is False
        assert any(r["port"] == server.server_port and r["state"] == "open" for r in full["records"])
        assert full["scaninfo"] and int(full["scaninfo"][0]["numservices"]) == 65535
        report["checks"]["full-tcp"]["requested_ports"] = 65535
        # Open + an unused adjacent closed port support Nmap's bounded OS test.
        closed = 1 if server.server_port != 1 else 2
        privileged = qualify("privileged-os", profile="service", ports=f"{server.server_port},{closed}",
                             os_detection=True, rate=100, timeout=120, host_timeout=120)
        assert any(r["state"] == "open" for r in privileged["records"])
        assert any(r["state"] == "closed" for r in privileged["records"])
        report["checks"]["privileged-os"]["os_matches"] = [m for h in privileged["hosts"] for m in h["os_matches"]]
        report["checks"]["privileged-os"]["limitation"] = "Namespace-authorized fingerprint only; match accuracy is not confirmed OS identity."
        udp = qualify("privileged-udp", profile="quick", ports=str(udp_server.server_address[1]),
                      udp=True, rate=20, timeout=30, host_timeout=20)
        assert any(r["protocol"] == "udp" and r["state"] == "open" for r in udp["records"])
        rules = ("add table inet cyberrecon_lab\n"
                 "add chain inet cyberrecon_lab input { type filter hook input priority 0; policy accept; }\n"
                 f"add rule inet cyberrecon_lab input tcp dport {closed} drop\n")
        firewall = subprocess.run(["nft", "-f", "-"], input=rules, capture_output=True, text=True, timeout=10)
        report["lab_firewall"] = {"command": ["nft", "-f", "-"], "rules": rules, "exit": firewall.returncode}
        assert firewall.returncode == 0
        filtered = qualify("filtered-tcp", profile="quick", ports=str(closed), rate=20, timeout=30, host_timeout=20)
        assert any(r["port"] == closed and r["state"] == "filtered" for r in filtered["records"])
        cancel = threading.Event()
        timer = threading.Timer(.3, cancel.set)
        timer.start()
        diagnostics = []
        try:
            result, raw = port_scan("127.0.0.1", Scope(["127.0.0.1"]), profile="full", rate=1, timeout=20,
                                    cancel=cancel, diagnostic=diagnostics.append)
            assert result["partial"] and result.get("failure_code") == "cancelled"
            (output / "cancelled.xml").write_bytes(raw)
        except ToolError as exc:
            assert exc.code == "cancelled"
        finally:
            timer.cancel()
        assert diagnostics and diagnostics[-1]["returncode"] is not None
        report["checks"]["cancellation-process-reaped"] = {"status": "PASS", "commands": diagnostics}
        timeout_diagnostics = []
        try:
            parsed, raw = port_scan("127.0.0.1", Scope(["127.0.0.1"]), profile="full", rate=1,
                                    timeout=10, host_timeout=120, diagnostic=timeout_diagnostics.append)
            assert parsed["partial"] and parsed.get("failure_code") == "timeout"
            (output / "timeout.xml").write_bytes(raw)
        except ToolError as exc:
            assert exc.code == "timeout"
        assert timeout_diagnostics and timeout_diagnostics[-1]["returncode"] is not None
        report["checks"]["timeout-process-reaped"] = {"status": "PASS", "commands": timeout_diagnostics}
        report["status"] = "PASS"
        save()
        print(json.dumps({"status": report["status"], "checks": list(report["checks"])}))
        return 0
    except Exception as exc:
        report["status"] = "FAIL"
        report["failure_type"] = type(exc).__name__
        save()
        raise
    finally:
        server.shutdown()
        server.server_close()
        thread.join(5)
        udp_server.shutdown()
        udp_server.server_close()
        udp_thread.join(5)


if __name__ == "__main__":
    raise SystemExit(main())
