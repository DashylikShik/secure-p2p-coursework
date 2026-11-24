"""One secure PING/PONG exchange, separate from DHT while Stage 4.1 is tested."""
from __future__ import annotations

import socket
import ssl
import threading
import uuid
from dataclasses import dataclass

from protocol import PING, PONG, make_frame, read_frame
from tls_channel import verify_expected_peer


@dataclass(frozen=True)
class ExchangeResult:
    version: str
    verified_id: str
    response: str


def one_server_connection(accepted: socket.socket, context: ssl.SSLContext,
                          expected_client_id: bytes, server_name: str = 'A',
                          actions: list[str] | None = None) -> ExchangeResult:
    """Every app action is performed only AFTER TLS and NodeID verification."""
    with context.wrap_socket(accepted, server_side=True) as protected:
        protected.settimeout(5.0)
        verified = verify_expected_peer(protected, expected_client_id)
        frame = read_frame(protected)
        if frame['type'] != PING or set(frame['payload']) != {'from', 'text'}:
            raise ValueError('Expected application PING with from/text')
        if actions is not None:
            actions.append(frame['payload']['text'])
        response = make_frame(PONG, {'from': server_name, 'text': 'TLS PONG'},
                              request_id=frame['request_id'])
        protected.sendall(response)
        return ExchangeResult(protected.version(), verified.hex(), 'PONG sent')


def one_client_connection(host: str, port: int, context: ssl.SSLContext,
                          expected_server_id: bytes, message: str,
                          expected_public_key: bytes | None = None) -> ExchangeResult:
    if not isinstance(message, str) or not message:
        raise ValueError('Message is required')
    rid = uuid.uuid4().bytes
    with socket.create_connection((host, port), timeout=5) as raw:
        raw.settimeout(5)
        with context.wrap_socket(raw, server_hostname=None) as protected:
            verified = verify_expected_peer(protected, expected_server_id, expected_public_key)
            protected.sendall(make_frame(PING, {'from': 'B', 'text': message}, request_id=rid))
            received = read_frame(protected)
            if received['type'] != PONG or received['request_id'] != rid:
                raise ValueError('TLS response has wrong type or request_id')
            if received['payload'] != {'from': 'A', 'text': 'TLS PONG'}:
                raise ValueError('Unexpected PONG body')
            return ExchangeResult(protected.version(), verified.hex(), 'PONG received')


class CapturingTcpRelay:
    """Tiny localhost observer; sees the TCP ciphertext only, not TLS keys."""
    def __init__(self, upstream_host: str, upstream_port: int):
        self.upstream = (upstream_host, upstream_port)
        self.captured = bytearray()
        self._guard = threading.Lock()
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.bind(('127.0.0.1', 0))
        self._server.listen(1)
        self.port = self._server.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        try:
            conn, _ = self._server.accept()
            with conn, socket.create_connection(self.upstream, timeout=5) as upstream:
                def pump(source: socket.socket, destination: socket.socket) -> None:
                    try:
                        while True:
                            chunk = source.recv(65536)
                            if not chunk:
                                break
                            with self._guard:
                                self.captured.extend(chunk)
                            destination.sendall(chunk)
                    except OSError:
                        pass
                    finally:
                        try:
                            destination.shutdown(socket.SHUT_WR)
                        except OSError:
                            pass
                pump_up = threading.Thread(target=pump, args=(conn, upstream), daemon=True)
                pump_down = threading.Thread(target=pump, args=(upstream, conn), daemon=True)
                pump_up.start()
                pump_down.start()
                pump_up.join(timeout=8)
                pump_down.join(timeout=8)
        except OSError:
            pass
        finally:
            self._server.close()

    def close(self) -> None:
        self._thread.join(timeout=8)
        try:
            self._server.close()
        except OSError:
            pass
