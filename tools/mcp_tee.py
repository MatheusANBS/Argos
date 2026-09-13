"""Diagnostic passthrough for the Argos MCP stdio server.

Spawns the real server and relays stdin/stdout verbatim, appending both
directions to a log file. It exists to answer "what does the MCP client
actually send, and what did the server actually reply" instead of guessing
from the client's summary. Point .mcp.json at this script only while
diagnosing; it adds a process hop and a log file, so it is not a normal
runtime path.

Usage (from .mcp.json):
    "command": "python",
    "args": ["E:\\\\Projetos\\\\Argos\\\\tools\\\\mcp_tee.py",
             "E:\\\\Projetos\\\\Argos\\\\install\\\\bin\\\\argos_runtime_memory_mcp.exe"]

The log path can be overridden with ARGOS_MCP_TEE_LOG.
"""

import os
import subprocess
import sys
import threading
from datetime import datetime, timezone

DEFAULT_LOG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mcp_tee.log")
LOG_PATH = os.environ.get("ARGOS_MCP_TEE_LOG", DEFAULT_LOG)

_log_lock = threading.Lock()
_log = open(LOG_PATH, "ab", buffering=0)


def record(direction: bytes, payload: bytes) -> None:
    stamp = datetime.now(timezone.utc).strftime("%H:%M:%S.%f").encode("ascii")
    with _log_lock:
        _log.write(b"[" + stamp + b"] " + direction + b" " + payload.rstrip(b"\r\n") + b"\n")


def pump(source, sink, direction: bytes) -> None:
    """Relay one direction byte-for-byte, logging each newline-delimited frame."""
    try:
        for line in iter(source.readline, b""):
            record(direction, line)
            sink.write(line)
            sink.flush()
    except Exception as error:  # never let the diagnostic kill the relay
        record(b"!!", repr(error).encode("utf-8", "replace"))
    finally:
        try:
            sink.close()
        except Exception:
            pass


def main() -> int:
    if len(sys.argv) < 2:
        sys.stderr.write("mcp_tee.py: missing server executable path\n")
        return 2
    command = sys.argv[1:]
    record(b"##", b"spawn " + " ".join(command).encode("utf-8", "replace"))

    child = subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=None,  # server logs go straight to the client's stderr, untouched
    )

    to_child = threading.Thread(
        target=pump, args=(sys.stdin.buffer, child.stdin, b"->"), daemon=True
    )
    from_child = threading.Thread(
        target=pump, args=(child.stdout, sys.stdout.buffer, b"<-"), daemon=True
    )
    to_child.start()
    from_child.start()

    code = child.wait()
    from_child.join(timeout=2)
    record(b"##", f"server exited with {code}".encode("ascii"))
    return code


if __name__ == "__main__":
    sys.exit(main())
