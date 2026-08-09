#!/usr/bin/env python3
"""
Dynamic IP authorization watchdog for gost proxy (Port Knocking / SPA).

Uses the iptables "recent" module so authorized IPs auto-expire:
  - Client knocks on :8799 with the right token → IP added to kernel recent-list.
  - Every *packet* the client sends through :8798 refreshes the last-seen timer.
  - After SESSION_TTL seconds of silence → IP automatically purged (--reap).
  - No per-IP iptables rules accumulate — only two static rules exist.

Unlike the v1 "insert-a-rule-forever" approach, this one actually cleans up
after disconnected clients.  The door does NOT stay wide open.
"""
import http.server
import socketserver
import subprocess
import logging
import os
import sys
import signal

# ── Configuration ──────────────────────────────────────────────
SECRET_TOKEN = "homio-666-open-the-door"
AUTH_PORT    = 8799
GOST_PORT    = 8798
SESSION_TTL  = 28800   # 8 hours – IP expires after this many seconds of silence
RECENT_NAME  = "GOST_AUTH"
RECENT_PROC  = f"/proc/net/xt_recent/{RECENT_NAME}"
LOG_FILE     = os.path.join(os.path.dirname(os.path.abspath(__file__)), "proxy-auth.log")
# ────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger("proxy-auth")


# ── iptables helpers ───────────────────────────────────────────

def iptables(*args, check=False):
    """Run an iptables(8) command, return CompletedProcess."""
    cmd = ["iptables"] + list(args)
    logger.debug("iptables: %s", " ".join(cmd))
    return subprocess.run(cmd, capture_output=True, text=True, check=check)


def rule_exists(*args):
    """True if the iptables rule already exists (checked via -C)."""
    return iptables("-C", *args).returncode == 0


def delete_all_rules():
    """
    Purge *every* INPUT rule referencing GOST_PORT.
    This handles both v1 leftovers (per-IP ACCEPT / bare DROP)
    and our own v2 rules so we can recreate them idempotently.
    """
    for target in ("ACCEPT", "DROP"):
        while True:
            r = iptables(
                "-D", "INPUT", "-p", "tcp",
                "--dport", str(GOST_PORT), "-j", target,
            )
            if r.returncode != 0:
                break
            logger.info("Cleaned up old %s rule for port %d.", target, GOST_PORT)


def ensure_firewall_rules():
    """
    Set up the two static iptables rules (order matters):

      1. If source IP is in the RECENT_NAME list *and* was seen within
         SESSION_TTL seconds → ACCEPT + update its last-seen timestamp.
      2. Everything else → DROP.

    These are the *only* rules for GOST_PORT.  No per-IP rules are ever added.
    """
    delete_all_rules()

    # Rule 1 – dynamic ACCEPT for recently-seen IPs
    if not rule_exists(
        "INPUT", "-p", "tcp", "--dport", str(GOST_PORT),
        "-m", "recent", "--name", RECENT_NAME,
        "--update", "--seconds", str(SESSION_TTL), "--reap",
        "-j", "ACCEPT",
    ):
        iptables(
            "-A", "INPUT", "-p", "tcp", "--dport", str(GOST_PORT),
            "-m", "recent", "--name", RECENT_NAME,
            "--update", "--seconds", str(SESSION_TTL), "--reap",
            "-j", "ACCEPT",
            check=True,
        )
        logger.info(
            "Rule added: recent --update --seconds %d → ACCEPT for port %d.",
            SESSION_TTL, GOST_PORT,
        )

    # Rule 2 – terminal DROP
    if not rule_exists(
        "INPUT", "-p", "tcp", "--dport", str(GOST_PORT), "-j", "DROP",
    ):
        iptables(
            "-A", "INPUT", "-p", "tcp",
            "--dport", str(GOST_PORT), "-j", "DROP",
            check=True,
        )
        logger.info("Rule added: DROP for port %d.", GOST_PORT)


# ── Kernel recent-list manipulation ────────────────────────────

def authorize_ip(ip):
    """
    Write the client IP into the kernel's recent-list so the
    iptables --update rule will match it.

    No iptables rule is created — just one line written to
    /proc/net/xt_recent/GOST_AUTH.  The kernel handles expiry.
    """
    # Ignore loopback – localhost is always allowed
    if ip in ("127.0.0.1", "::1"):
        return True, f"IP {ip} is localhost – already authorized."

    # Check current state (best-effort, proc file might not be readable)
    already_present = False
    try:
        with open(RECENT_PROC, "r") as f:
            for line in f:
                if line.startswith(f"src={ip} "):
                    already_present = True
                    break
    except (FileNotFoundError, PermissionError):
        pass

    if already_present:
        return True, f"IP {ip} is already authorized (TTL refreshed by traffic)."

    # Write +IP to the kernel list
    try:
        with open(RECENT_PROC, "w") as f:
            f.write(f"+{ip}\n")
        logger.info("IP %s added to %s (TTL=%ds).", ip, RECENT_NAME, SESSION_TTL)
        return True, (
            f"Success! IP {ip} has been whitelisted.\n"
            f"TTL: {SESSION_TTL}s ({SESSION_TTL//3600}h) of silence → auto-purge."
        )
    except FileNotFoundError:
        logger.error(
            "%s not found – is the iptables recent module loaded? "
            "Try: modprobe xt_recent", RECENT_PROC,
        )
        return False, "Server error: kernel recent module not available."
    except PermissionError:
        logger.error("Permission denied writing to %s – must run as root.", RECENT_PROC)
        return False, "Server error: insufficient permissions."


def list_authorized_ips():
    """Return currently authorized IPs (for the /status endpoint)."""
    ips = []
    try:
        with open(RECENT_PROC, "r") as f:
            for line in f:
                # Format: src=1.2.3.4 ttl:12345 last_seen:1234567890 ...
                if line.startswith("src="):
                    ips.append(line.split()[0].replace("src=", ""))
    except (FileNotFoundError, PermissionError):
        pass
    return ips


# ── HTTP handler ───────────────────────────────────────────────

class AuthHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        expected_auth = f"/auth?token={SECRET_TOKEN}"

        if self.path == expected_auth:
            client_ip = self.client_address[0]
            logger.info("Auth request from %s — token OK", client_ip)

            ok, msg = authorize_ip(client_ip)
            code = 200 if ok else 500
            self.send_response(code)
            self.end_headers()
            self.wfile.write((msg + "\n").encode())

        elif self.path == "/status":
            # Optional: show currently active IPs (token-protected too, or open)
            ips = list_authorized_ips()
            self.send_response(200)
            self.end_headers()
            body = f"Active IPs ({len(ips)}):\n" + "\n".join(f"  - {ip}" for ip in ips) + "\n"
            self.wfile.write(body.encode())

        else:
            logger.warning("Bad knock from %s (path=%s)", self.client_address[0], self.path)
            self.send_response(403)
            self.end_headers()
            self.wfile.write(b"Go away, hacker!\n")

    def log_message(self, fmt, *args):
        logger.info("%s - %s", self.client_address[0], fmt % args)


# ── Main ───────────────────────────────────────────────────────

def main():
    ensure_firewall_rules()

    def _on_signal(signum, frame):
        logger.info("Received signal %d, shutting down.", signum)
        # Leave firewall rules in place – port stays protected.
        sys.exit(0)

    signal.signal(signal.SIGTERM, _on_signal)
    signal.signal(signal.SIGINT, _on_signal)

    with socketserver.TCPServer(("", AUTH_PORT), AuthHandler) as httpd:
        logger.info("Auth watchdog listening on 0.0.0.0:%d (TTL=%ds) …", AUTH_PORT, SESSION_TTL)
        httpd.serve_forever()


if __name__ == "__main__":
    main()
