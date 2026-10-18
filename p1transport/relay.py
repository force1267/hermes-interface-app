"""P1 relay: the forwarding hop. Bytes only.

Opens a listener, dials the provider, and pumps bytes both ways.
No parsing, no renderer, no registry, no policy, no product state —
it cannot even see envelope boundaries, only TCP segments.
kill() closes the sockets for real (abrupt close, in-flight bytes
may be lost); that is the fault-injection half of P1.
"""
import socket
import threading


class Relay:
    def __init__(self, upstream_host, upstream_port):
        self.upstream_host = upstream_host
        self.upstream_port = upstream_port
        self._listener = None
        self._socks = []
        self._lock = threading.Lock()
        self._closed = False
        self._thread = None

    def start(self):
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(8)
        self._thread = threading.Thread(target=self._accept_loop,
                                        daemon=True)
        self._thread.start()
        return self._listener.getsockname()[1]

    @property
    def port(self):
        return self._listener.getsockname()[1]

    def _accept_loop(self):
        while not self._closed:
            try:
                downstream, _ = self._listener.accept()
            except OSError:
                return
            try:
                upstream = socket.create_connection(
                    (self.upstream_host, self.upstream_port), timeout=5)
            except OSError:
                try:
                    downstream.close()
                except OSError:
                    pass
                continue
            with self._lock:
                self._socks += [downstream, upstream]
            threading.Thread(target=self._pump,
                             args=(downstream, upstream), daemon=True).start()
            threading.Thread(target=self._pump,
                             args=(upstream, downstream), daemon=True).start()

    @staticmethod
    def _pump(src, dst):
        try:
            while True:
                chunk = src.recv(65536)
                if not chunk:
                    return
                dst.sendall(chunk)
        except OSError:
            return

    def kill(self):
        """Real socket kill: abort every live connection + the listener."""
        self._closed = True
        with self._lock:
            socks, self._socks = self._socks + [self._listener], []
        for s in socks:
            if s is None:
                continue
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                s.close()
            except OSError:
                pass
