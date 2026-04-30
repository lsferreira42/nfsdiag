#!/usr/bin/env python3
import os
import socket
import threading

port = int(os.environ.get("LISTEN_PORT", "2049"))
message = os.environ.get("LISTEN_MESSAGE", "nfs-doctor dummy listener\n").encode()

sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(("::", port))
sock.listen(64)
print(f"[fixture] listening on TCP/{port}", flush=True)

while True:
    conn, addr = sock.accept()
    def handle(c):
        try:
            c.sendall(message)
        except Exception:
            pass
        finally:
            c.close()
    threading.Thread(target=handle, args=(conn,), daemon=True).start()
