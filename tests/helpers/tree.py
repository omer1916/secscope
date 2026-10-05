"""Spawn a grandchild that listens on a TCP port, print both pids and the port, then wait.

Used to prove that cancelling kills the whole process tree and frees ports.
"""

import socket
import subprocess
import sys
import time

if len(sys.argv) > 1 and sys.argv[1] == "grandchild":
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen()
    print(srv.getsockname()[1], flush=True)
    time.sleep(600)
else:
    child = subprocess.Popen(
        [sys.executable, __file__, "grandchild"], stdout=subprocess.PIPE, text=True
    )
    assert child.stdout is not None
    port = child.stdout.readline().strip()
    print(f"{child.pid} {port}", flush=True)
    time.sleep(600)
