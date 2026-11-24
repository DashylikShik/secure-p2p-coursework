"""Учебный узел Kademlia: подписанные RPC поверх TCP или взаимного TLS 1.3.

Если переданы TLS credentials, узел НИКОГДА не понижает соединение до открытого TCP.
Открытый TCP оставлен по умолчанию только для воспроизведения старых пилотных
демонстраций; реальные испытания этапа 4 используют TLS явно.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import math
import socket
import ssl
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from replay_guard import ReplayGuard
from pathlib import Path
from typing import Any

from identity import Identity, load_or_create_identity, verify_node_id, verify_signature
from protocol import (
    PING, PONG, FIND_NODE_REQUEST, FIND_NODE_RESPONSE,
    STORE_REQUEST, STORE_RESPONSE, FIND_VALUE_REQUEST, FIND_VALUE_RESPONSE,
    make_frame, read_frame
)
from dht_records import LocalRecordStore, RecordRejected, verify_node_record
from tls_channel import (TlsCredentials, server_tls_context, client_tls_context,
                         verify_expected_peer, verified_certificate_identity,
                         check_local_tls_identity)
from routing import Contact, RoutingTable, xor_distance, bucket_index, validate_node_id

DOMAIN = b'coursework-kademlia-rpc-v1:'
MAX_NEIGHBORS = 3


def canonical_bytes(value: dict) -> bytes:
    """Единое байтовое представление для подписи на обеих сторонах."""
    return json.dumps(value, sort_keys=True, ensure_ascii=True,
                      separators=(',', ':'), allow_nan=False).encode('utf-8')


def make_envelope(identity: Identity, request_id: bytes, kind: str,
                  body: dict, host: str, port: int, *,
                  session_id: bytes | None = None, message_id: bytes | None = None) -> dict:
    """Подпись связывает отправителя, адрес, тип RPC и request_id."""
    unsigned = {
        'node_id': identity.node_id.hex(),
        'public_key': identity.public_key_bytes.hex(),
        'host': host,
        'port': port,
        'kind': kind,
        'request_id': request_id.hex(),
        'body': body,
    }
    if (session_id is None) != (message_id is None):
        raise ValueError('session_id и message_id должны задаваться вместе')
    if session_id is not None:
        if type(session_id) is not bytes or len(session_id) != 16 or type(message_id) is not bytes or len(message_id) != 16:
            raise ValueError('session_id/message_id должны иметь длину 16 байт')
        unsigned['session_id'] = session_id.hex()
        unsigned['message_id'] = message_id.hex()
    result = dict(unsigned)
    result['signature'] = identity.sign(DOMAIN + canonical_bytes(unsigned)).hex()
    return result


def _strict_hex(value: Any, length: int) -> bytes:
    if not isinstance(value, str) or len(value) != length * 2:
        raise ValueError('Неверная длина hex-поля')
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError('Повреждённое hex-поле') from exc
    if len(raw) != length:
        raise ValueError('Неверная длина байтового поля')
    return raw


def _local_contact(node_id: bytes, host: str, port: int) -> Contact:
    # Этот учебный стенд слушает только loopback. Не открываем внешние адреса.
    if host != '127.0.0.1':
        raise ValueError('Пилот поддерживает только 127.0.0.1')
    return Contact(node_id, host, port)


def verify_envelope(envelope: dict, request_id: bytes, expected_kind: str,
                    expected_id: bytes | None = None,
                    expected_key: bytes | None = None, *,
                    require_replay: bool = False,
                    expected_session_id: bytes | None = None,
                    expected_message_id: bytes | None = None) -> tuple[Contact, bytes, dict]:
    """Проверить подписанный RPC. Не означает полную TLS-аутентификацию!"""
    if not isinstance(envelope, dict):
        raise ValueError('RPC должен быть JSON-объектом')
    base_fields = {'node_id', 'public_key', 'host', 'port',
                   'kind', 'request_id', 'body', 'signature'}
    replay_fields = {'session_id', 'message_id'}
    fields = set(envelope)
    if fields not in (base_fields, base_fields | replay_fields):
        raise ValueError('Неверные поля подписанного RPC')
    has_replay = fields == base_fields | replay_fields
    if require_replay and not has_replay:
        raise ValueError('TLS RPC требует session_id и message_id')
    if has_replay:
        session = _strict_hex(envelope['session_id'], 16)
        message = _strict_hex(envelope['message_id'], 16)
        if expected_session_id is not None and session != expected_session_id:
            raise ValueError('session_id ответа не совпадает')
        if expected_message_id is not None and message != expected_message_id:
            raise ValueError('message_id ответа не совпадает')
    elif expected_session_id is not None or expected_message_id is not None:
        raise ValueError('Ответ без session_id или message_id')
    public_key = _strict_hex(envelope['public_key'], 32)
    claimed_id = _strict_hex(envelope['node_id'], 32)
    signature = _strict_hex(envelope['signature'], 64)
    if not verify_node_id(claimed_id, public_key):
        raise ValueError('NodeID не соответствует открытому ключу')
    if expected_id is not None and claimed_id != expected_id:
        raise ValueError('Ответил другой NodeID')
    if expected_key is not None and public_key != expected_key:
        raise ValueError('Ответил другой открытый ключ')
    if envelope['kind'] != expected_kind or envelope['request_id'] != request_id.hex():
        raise ValueError('Тип RPC или request_id не совпадает')
    if not isinstance(envelope['body'], dict):
        raise ValueError('body должен быть JSON-объектом')
    contact = _local_contact(claimed_id, envelope['host'], envelope['port'])
    unsigned = {k: v for k, v in envelope.items() if k != 'signature'}
    if not verify_signature(public_key, DOMAIN + canonical_bytes(unsigned), signature):
        raise ValueError('Неверная цифровая подпись RPC')
    return contact, public_key, envelope['body']


def wire_contact(contact: Contact, public_key: bytes) -> dict:
    if not verify_node_id(contact.node_id, public_key):
        raise ValueError('NodeID контакта не совпадает с ключом')
    return {'node_id': contact.node_id.hex(), 'public_key': public_key.hex(),
            'host': contact.host, 'port': contact.port}


def parse_contact(value: dict) -> tuple[Contact, bytes]:
    if not isinstance(value, dict) or set(value) != {'node_id', 'public_key', 'host', 'port'}:
        raise ValueError('Неправильная контактная запись')
    node_id = _strict_hex(value['node_id'], 32)
    public_key = _strict_hex(value['public_key'], 32)
    if not verify_node_id(node_id, public_key):
        raise ValueError('Подмена NodeID в найденном контакте')
    return _local_contact(node_id, value['host'], value['port']), public_key


@dataclass
class LookupResult:
    target: str
    found: bool = False
    result_host: str | None = None
    result_port: int | None = None
    iterations: int = 0
    rpc_count: int = 0
    errors: list[str] = field(default_factory=list)
    queried_by_round: list[list[str]] = field(default_factory=list)
    elapsed_ms: float = 0.0

    def as_dict(self) -> dict:
        return {
            'target': self.target,
            'found': self.found,
            'result_host': self.result_host,
            'result_port': self.result_port,
            'iterations': self.iterations,
            'rpc_count': self.rpc_count,
            'errors': self.errors,
            'queried_by_round': self.queried_by_round,
            'elapsed_ms': round(self.elapsed_ms, 3),
        }


@dataclass
class ValueLookupResult:
    """Отчёт сетевого FIND_VALUE: запись возвращается только после проверки подписи.

    Запись публичная; закрытых ключей в отчёте нет.
    """
    key: str
    found: bool = False
    record: dict | None = None
    iterations: int = 0
    rpc_count: int = 0
    errors: list[str] = field(default_factory=list)
    queried_by_round: list[list[str]] = field(default_factory=list)
    elapsed_ms: float = 0.0

    def as_dict(self) -> dict:
        return {
            'key': self.key, 'found': self.found,
            'record_owner': self.record['node_id'] if self.record else None,
            'record_sequence': self.record['sequence_number'] if self.record else None,
            'iterations': self.iterations, 'rpc_count': self.rpc_count,
            'errors': self.errors, 'queried_by_round': self.queried_by_round,
            'elapsed_ms': round(self.elapsed_ms, 3),
        }


@dataclass
class ReplicaWriteResult:
    """Проверяемый отчёт о выборе трёх хранителей и подтверждениях STORE."""
    key: str
    replication_factor: int = 3
    required_acks: int = 2
    selected: list[dict] = field(default_factory=list)
    acknowledgements: list[dict] = field(default_factory=list)
    discovery_rpc: int = 0
    discovery_iterations: int = 0
    discovery_errors: list[str] = field(default_factory=list)
    succeeded: bool = False
    elapsed_ms: float = 0.0

    def as_dict(self) -> dict:
        return {
            'key': self.key, 'replication_factor': self.replication_factor,
            'required_acks': self.required_acks, 'selected': self.selected,
            'acknowledgements': self.acknowledgements,
            'ack_count': sum(row['ack'] for row in self.acknowledgements),
            'stored_copies': sum(row['ack'] for row in self.acknowledgements),
            'discovery_rpc': self.discovery_rpc,
            'discovery_iterations': self.discovery_iterations,
            'discovery_errors': self.discovery_errors,
            'succeeded': self.succeeded,
            'elapsed_ms': round(self.elapsed_ms, 3),
        }


class DHTNode:
    """Отдельный узел: свой сокет, identity, k-buckets и известные контакты."""

    def __init__(self, identity: Identity, name: str, port: int = 0, *,
                 host: str = '127.0.0.1', k: int = 3, alpha: int = 3,
                 timeout: float = 1.5,
                 tls_credentials: TlsCredentials | None = None):
        if host != '127.0.0.1' or not (0 <= port <= 65535):
            raise ValueError('Этот пилот работает только на localhost')
        if k != 3 or alpha != 3:
            raise ValueError('Для упрощённого уровня установлены k=3, ALPHA=3')
        self.identity = identity
        self.name = name
        self.host = host
        self.port = port
        self.k = k
        self.alpha = alpha
        self.timeout = timeout
        # Без tls_credentials сохраняем прежние демонстрации. В TLS-режиме
        # оба контекста требуют TLSv1.3 + сертификат с доверенной CA.
        if tls_credentials is not None:
            check_local_tls_identity(tls_credentials, identity.node_id)
        self._tls_server_context = (server_tls_context(tls_credentials)
                                    if tls_credentials is not None else None)
        self._tls_client_context = (client_tls_context(tls_credentials)
                                    if tls_credentials is not None else None)
        self.tls_enabled = tls_credentials is not None
        self._tls_accepted = 0
        self._tls_outbound = 0
        self.routing = RoutingTable(identity.node_id, k)
        # Локальная DHT-база: закрытый ключ здесь никогда не хранится.
        self.record_store = LocalRecordStore()
        # Кэш только ключей ИЗВЕСТНЫХ проверенных контактов, не каталог сети.
        self._keys: dict[bytes, bytes] = {}
        self._lock = threading.RLock()
        self._server: socket.socket | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._refresh_stop = threading.Event()
        self._refresh_thread: threading.Thread | None = None
        self._refresh_cursor = 0
        self._refresh_runs = 0
        self._refresh_errors: list[str] = []
        self._probe_events: list[dict] = []
        # Shared across all TLS connections of this node, not per socket.
        # Old legacy plaintext examples remain explicitly unprotected.
        self._replay_guard = ReplayGuard(max_entries=4096, window_seconds=3600.0)

    @property
    def contact(self) -> Contact:
        if not self.port:
            raise RuntimeError('Сначала вызовите start()')
        return Contact(self.identity.node_id, self.host, self.port)

    def start(self) -> None:
        if self._server is not None:
            raise RuntimeError('Узел уже запущен')
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.host, self.port))
        self.port = server.getsockname()[1]
        server.listen(32)
        server.settimeout(0.15)
        self._stop.clear()
        self._server = server
        self._thread = threading.Thread(target=self._serve, daemon=True,
                                        name=f'DHT-{self.name}')
        self._thread.start()

    def stop(self) -> None:
        self.stop_periodic_refresh()
        self._stop.set()
        if self._server is not None:
            self._server.close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=2)
            self._thread = None

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn: socket.socket) -> None:
        """Verify TLS peer before reading/acting on any DHT frame."""
        with conn:
            conn.settimeout(self.timeout)
            try:
                if self._tls_server_context is None:
                    self._handle_connection(conn, None, None)
                else:
                    # No fallback to plaintext, even if handshake fails.
                    with self._tls_server_context.wrap_socket(conn, server_side=True) as protected:
                        tls_peer_id, tls_peer_key = verified_certificate_identity(protected)
                        with self._lock:
                            self._tls_accepted += 1
                        self._handle_connection(protected, tls_peer_id, tls_peer_key)
            except (ValueError, ConnectionError, OSError, TypeError):
                # One malformed/unauthenticated connection cannot stop the node.
                return

    def _handle_connection(self, channel: socket.socket, tls_peer_id: bytes | None,
                           tls_peer_key: bytes | None) -> None:
        # One authenticated TLS session can contain several DHT frames.
        # ReplayGuard is per node, so a fresh TLS connection cannot bypass it.
        while not self._stop.is_set():
            self._handle_frame(channel, tls_peer_id, tls_peer_key)

    def _handle_frame(self, channel: socket.socket, tls_peer_id: bytes | None,
                      tls_peer_key: bytes | None) -> None:
        frame = read_frame(channel)
        if frame['type'] == PING:
            expected_kind, out_type, out_kind = 'PING', PONG, 'PONG'
        elif frame['type'] == FIND_NODE_REQUEST:
            expected_kind, out_type, out_kind = 'FIND_NODE_REQUEST', FIND_NODE_RESPONSE, 'FIND_NODE_RESPONSE'
        elif frame['type'] == STORE_REQUEST:
            expected_kind, out_type, out_kind = 'STORE_REQUEST', STORE_RESPONSE, 'STORE_RESPONSE'
        elif frame['type'] == FIND_VALUE_REQUEST:
            expected_kind, out_type, out_kind = 'FIND_VALUE_REQUEST', FIND_VALUE_RESPONSE, 'FIND_VALUE_RESPONSE'
        else:
            return
        sender, key, body = verify_envelope(frame['payload'], frame['request_id'], expected_kind,
                                               expected_id=tls_peer_id, expected_key=tls_peer_key,
                                               require_replay=tls_peer_id is not None)
        if tls_peer_id is not None:
            # Mark a signed request as used BEFORE routing-table/storage side effects.
            # Global for node process, not merely this TLS session.
            self._replay_guard.check_and_mark(sender.node_id,
                bytes.fromhex(frame['payload']['session_id']),
                bytes.fromhex(frame['payload']['message_id']))
        # В таблицу не попадает неподписанный или некорректный NodeID.
        self._remember(sender, key)
        if frame['type'] == PING:
            answer = {'ok': True}
        elif frame['type'] == FIND_NODE_REQUEST:
            target = _strict_hex(body.get('target'), 32)
            answer = {'contacts': self._nearest_wire_contacts(target, sender.node_id)}
        elif frame['type'] == STORE_REQUEST:
            if set(body) != {'key', 'record'}:
                raise ValueError('STORE: неверные поля body')
            record_key = _strict_hex(body['key'], 32)
            signed_record = body['record']
            if verify_node_record(signed_record) != record_key:
                raise RecordRejected('STORE: ключ не соответствует подписанной записи')
            with self._lock:
                outcome = self.record_store.put(signed_record)
            answer = {'key': record_key.hex(), 'status': outcome}
        else:
            if set(body) != {'key'}:
                raise ValueError('FIND_VALUE: неверные поля body')
            record_key = _strict_hex(body['key'], 32)
            with self._lock:
                signed_record = self.record_store.get(record_key)
            if signed_record is None:
                answer = {'key': record_key.hex(), 'record': None,
                          'contacts': self._nearest_wire_contacts(record_key, sender.node_id)}
            else:
                answer = {'key': record_key.hex(), 'record': signed_record,
                          'contacts': []}
        replay_kwargs = ({'session_id': bytes.fromhex(frame['payload']['session_id']),
                          'message_id': bytes.fromhex(frame['payload']['message_id'])}
                         if tls_peer_id is not None else {})
        reply = make_frame(out_type, make_envelope(self.identity, frame['request_id'],
                                out_kind, answer, self.host, self.port, **replay_kwargs),
                           request_id=frame['request_id'])
        channel.sendall(reply)
    def _nearest_wire_contacts(self, target: bytes, exclude_id: bytes) -> list[dict]:
        """Отдать только известные контакты, без скрытого глобального каталога."""
        with self._lock:
            near = self.routing.nearest(target, self.k)
            return [wire_contact(c, self._keys[c.node_id]) for c in near
                    if c.node_id != exclude_id and c.node_id in self._keys]

    def _probe(self, contact: Contact, expected_key: bytes) -> bool:
        try:
            self._call(contact.host, contact.port, PING, 'PING', PONG,
                       'PONG', {}, expected_id=contact.node_id, expected_key=expected_key)
            return True
        except (ValueError, OSError, ConnectionError):
            return False

    def probe_history(self) -> list[dict]:
        """Краткий журнал проверок старого контакта (без секретных ключей)."""
        with self._lock:
            return list(self._probe_events)

    def _remember(self, contact: Contact, key: bytes) -> str:
        """Запомнить подписанный контакт, проверяя живость LRU по настоящему RPC.

        Сетевой PING выполняется ВНЕ блокировки: иначе при взаимном вызове
        двух узлов возможны тайм-ауты даже на живых контактах.
        После PING повторно проверяем, что старейший контакт не изменился.
        """
        if contact.node_id == self.identity.node_id:
            return 'ignored_self'
        if not verify_node_id(contact.node_id, key):
            raise ValueError('Контакт заявил чужой NodeID')
        for _ in range(4):
            with self._lock:
                old_key = self._keys.get(contact.node_id)
                if old_key is not None and old_key != key:
                    raise ValueError('Подмена ключа существующего контакта')
                status = self.routing.observe(contact)
                if status != 'needs_ping':
                    if status in ('added', 'updated', 'replaced'):
                        self._keys[contact.node_id] = key
                        self._prune_keys_locked()
                    return status
                index = bucket_index(self.identity.node_id, contact.node_id)
                oldest = self.routing.bucket_contents()[index][0]
                oldest_key = self._keys[oldest.node_id]
            # Нет удержания self._lock во время TCP-вызова.
            alive = self._probe(oldest, oldest_key)
            with self._lock:
                current = self.routing.bucket_contents().get(index, [])
                if not current or current[0] != oldest or self._keys.get(oldest.node_id) != oldest_key:
                    continue  # параллельная модификация: повторим выбор LRU
                status = self.routing.observe(contact, ping_oldest=lambda _: alive)
                self._probe_events.append({
                    'bucket': index, 'oldest': oldest.short_id,
                    'new': contact.short_id, 'alive': alive, 'decision': status,
                })
                if len(self._probe_events) > 100:
                    self._probe_events.pop(0)
                if status in ('added', 'updated', 'replaced'):
                    self._keys[contact.node_id] = key
                    self._prune_keys_locked()
                return status
        # При конкурирующих изменениях безопаснее отложить добавление.
        return 'needs_ping'

    def _prune_keys_locked(self) -> None:
        live = {c.node_id for values in self.routing.bucket_contents().values() for c in values}
        self._keys = {node_id: pk for node_id, pk in self._keys.items() if node_id in live}

    def _call(self, host: str, port: int, out_type: int, out_kind: str,
              reply_type: int, reply_kind: str, body: dict, *,
              expected_id: bytes | None = None,
              expected_key: bytes | None = None) -> tuple[Contact, bytes, dict]:
        request_id = uuid.uuid4().bytes
        # Each _call opens a fresh TLS connection. Both IDs are signed and
        # echoed by the server; message_id stays unique across connections.
        session_id = uuid.uuid4().bytes if self.tls_enabled else None
        message_id = uuid.uuid4().bytes if self.tls_enabled else None
        replay_kwargs = ({'session_id': session_id, 'message_id': message_id}
                         if self.tls_enabled else {})
        payload = make_envelope(self.identity, request_id, out_kind, body,
                                self.host, self.port, **replay_kwargs)
        frame = make_frame(out_type, payload, request_id=request_id)
        if self._tls_client_context is not None and expected_id is None:
            raise ValueError('TLS RPC требует ожидаемый NodeID: запрещён непроверенный peer')
        with socket.create_connection((host, port), timeout=self.timeout) as raw:
            raw.settimeout(self.timeout)
            if self._tls_client_context is None:
                raw.sendall(frame)
                response = read_frame(raw)
            else:
                with self._tls_client_context.wrap_socket(raw, server_hostname=None) as protected:
                    # Verify certificate AND pin BEFORE sending signed DHT request.
                    verify_expected_peer(protected, expected_id, expected_key)
                    with self._lock:
                        self._tls_outbound += 1
                    protected.sendall(frame)
                    response = read_frame(protected)
        if response['type'] != reply_type or response['request_id'] != request_id:
            raise ValueError('Неверный тип ответа или request_id')
        contact, key, result = verify_envelope(response['payload'], request_id, reply_kind,
                                             expected_id=expected_id, expected_key=expected_key,
                                             require_replay=self.tls_enabled,
                                             expected_session_id=session_id,
                                             expected_message_id=message_id)
        if (contact.host, contact.port) != (host, port):
            raise ValueError('Ответ содержит другой объявленный адрес')
        return contact, key, result

    def bootstrap(self, address: tuple[str, int], *,
                  expected_node_id: bytes | None = None,
                  expected_public_key: bytes | None = None) -> Contact:
        """Bootstrap: TLS requires a configured/pinned seed identity.

        Pre-provisioned (seed address + NodeID + public key) is NOT a global
        node directory: only the first known contact is configured.
        """
        if self.tls_enabled and (expected_node_id is None or expected_public_key is None):
            raise ValueError('TLS bootstrap: нужен закреплённый NodeID и открытый ключ seed-узла')
        contact, key, _ = self._call(address[0], address[1], PING, 'PING',
                                     PONG, 'PONG', {}, expected_id=expected_node_id,
                                     expected_key=expected_public_key)
        self._remember(contact, key)
        return contact

    def ping(self, peer: Contact) -> bool:
        with self._lock:
            key = self._keys.get(peer.node_id)
        try:
            contact, public_key, _ = self._call(peer.host, peer.port, PING, 'PING',
                    PONG, 'PONG', {}, expected_id=peer.node_id, expected_key=key)
            self._remember(contact, public_key)
            return True
        except (ValueError, OSError, ConnectionError):
            return False

    def _find_node(self, peer: Contact, key: bytes | None,
                   target_id: bytes) -> list[tuple[Contact, bytes]]:
        sender, actual_key, body = self._call(peer.host, peer.port,
                FIND_NODE_REQUEST, 'FIND_NODE_REQUEST',
                FIND_NODE_RESPONSE, 'FIND_NODE_RESPONSE',
                {'target': target_id.hex()}, expected_id=peer.node_id,
                expected_key=key)
        self._remember(sender, actual_key)
        raw_contacts = body.get('contacts')
        if not isinstance(raw_contacts, list) or len(raw_contacts) > self.k:
            raise ValueError('Неверное количество контактов FIND_NODE')
        return [parse_contact(raw) for raw in raw_contacts]

    def _discover_live_contacts(self, target: bytes, max_rounds: int = 20) -> tuple[list[Contact], int, int, list[str]]:
        """Найти доступные адреса через существующие FIND_NODE RPC.

        Список известных ID не передаётся извне. Каждый удалённый контакт
        включается в кандидаты только после ответа с проверенной подписью.
        Свой контакт включён в результат без сетевого запроса.
        """
        validate_node_id(target)
        if type(max_rounds) is not int or max_rounds < 1:
            raise ValueError('max_rounds должен быть положительным целым')
        if self._server is None:
            raise RuntimeError('Сначала запустите узел')
        with self._lock:
            initial = self.routing.nearest(target, 256)
            known_keys = dict(self._keys)
        candidates = {contact.node_id: contact for contact in initial}
        verified = {self.identity.node_id: self.contact}
        queried: set[bytes] = set()
        errors: list[str] = []
        rpc_count = 0
        rounds = 0
        for _ in range(max_rounds):
            available = [c for c in candidates.values() if c.node_id not in queried]
            if not available:
                break
            available.sort(key=lambda c: (xor_distance(c.node_id, target), c.node_id))
            selected = available[:self.alpha]
            queried.update(c.node_id for c in selected)
            rounds += 1
            rpc_count += len(selected)
            with ThreadPoolExecutor(max_workers=self.alpha) as pool:
                jobs = {pool.submit(self._find_node, peer, known_keys.get(peer.node_id), target): peer
                        for peer in selected}
                for future in as_completed(jobs):
                    peer = jobs[future]
                    try:
                        neighbors = future.result()
                        verified[peer.node_id] = peer
                        for candidate, public_key in neighbors:
                            if candidate.node_id == self.identity.node_id:
                                continue
                            old_key = known_keys.get(candidate.node_id)
                            if old_key is not None and old_key != public_key:
                                raise ValueError('Противоречащий ключ контакта')
                            if candidate.node_id not in candidates:
                                candidates[candidate.node_id] = candidate
                            known_keys[candidate.node_id] = public_key
                    except (OSError, ConnectionError, ValueError) as exc:
                        errors.append(f'{peer.short_id}: {type(exc).__name__}: {exc}')
        return sorted(verified.values(), key=lambda c: (xor_distance(c.node_id, target), c.node_id)), rpc_count, rounds, errors

    def store_replicated(self, record: dict, *, max_rounds: int = 20) -> ReplicaWriteResult:
        """Разместить подписанную NodeRecord на R=3 ближайших живых узлах.

        Успех операции = минимум два действительных подтверждения из трёх
        выбранных хранителей. В число хранителей включается и этот узел,
        если он входит в тройку ближайших по XOR к DHT-ключу записи.
        """
        record_key = verify_node_record(record)  # до любого сетевого обращения
        begin = time.perf_counter()
        result = ReplicaWriteResult(key=record_key.hex())
        reachable, rpc, iterations, errors = self._discover_live_contacts(record_key, max_rounds)
        result.discovery_rpc = rpc
        result.discovery_iterations = iterations
        result.discovery_errors = errors
        selected = reachable[:result.replication_factor]
        for peer in selected:
            result.selected.append({
                'node_id': peer.node_id.hex(), 'host': peer.host, 'port': peer.port,
                'xor_distance': xor_distance(peer.node_id, record_key),
            })
        for peer in selected:
            ack = False
            try:
                if peer.node_id == self.identity.node_id:
                    with self._lock:
                        status = self.record_store.put(record)
                else:
                    status = self.store_record_at(peer, record)
                ack = status in ('stored', 'updated', 'duplicate')
                description = status
            except (OSError, ConnectionError, ValueError) as exc:
                description = f'{type(exc).__name__}: {exc}'
            result.acknowledgements.append({
                'node_id': peer.node_id.hex(), 'ack': ack, 'status': description,
            })
        result.succeeded = (len(selected) == result.replication_factor and
                            sum(item['ack'] for item in result.acknowledgements) >= result.required_acks)
        result.elapsed_ms = (time.perf_counter() - begin) * 1000
        return result

    def store_record_at(self, peer: Contact, record: dict) -> str:
        """Сетевой STORE одному выбранному хранителю (без репликации пока).

        Вызывающий должен заранее узнать peer через bootstrap/FIND_NODE.
        Это не распределение на R=3 ближайших узлах — следующий подэтап.
        """
        key = verify_node_record(record)
        with self._lock:
            expected_key = self._keys.get(peer.node_id)
        sender, public_key, body = self._call(
            peer.host, peer.port, STORE_REQUEST, 'STORE_REQUEST',
            STORE_RESPONSE, 'STORE_RESPONSE', {'key': key.hex(), 'record': record},
            expected_id=peer.node_id, expected_key=expected_key)
        if set(body) != {'key', 'status'} or body['key'] != key.hex() or body['status'] not in (
                'stored', 'updated', 'duplicate'):
            raise ValueError('STORE: некорректное подтверждение')
        self._remember(sender, public_key)
        return body['status']

    def _find_value(self, peer: Contact, expected_key: bytes | None,
                    record_key: bytes) -> tuple[dict | None, list[tuple[Contact, bytes]]]:
        sender, public_key, body = self._call(
            peer.host, peer.port, FIND_VALUE_REQUEST, 'FIND_VALUE_REQUEST',
            FIND_VALUE_RESPONSE, 'FIND_VALUE_RESPONSE', {'key': record_key.hex()},
            expected_id=peer.node_id, expected_key=expected_key)
        self._remember(sender, public_key)
        if set(body) != {'key', 'record', 'contacts'} or body['key'] != record_key.hex():
            raise ValueError('FIND_VALUE: неверный ответ')
        raw = body['record']
        raw_contacts = body['contacts']
        if not isinstance(raw_contacts, list) or len(raw_contacts) > self.k:
            raise ValueError('FIND_VALUE: неверный список контактов')
        if raw is not None:
            if raw_contacts or verify_node_record(raw) != record_key:
                raise RecordRejected('FIND_VALUE: повреждённая или чужая запись')
            return raw, []
        return None, [parse_contact(entry) for entry in raw_contacts]

    def lookup_value(self, record_key: bytes, *, max_rounds: int = 20) -> ValueLookupResult:
        """Итеративный FIND_VALUE (ALPHA=3), цель — ключ подписанной записи.

        Результат успешен, только если получена действительная подписанная запись.
        Отсутствующий ключ возвращает found=False без исключения.
        """
        validate_node_id(record_key)
        started = time.perf_counter()
        result = ValueLookupResult(key=record_key.hex())
        with self._lock:
            local = self.record_store.get(record_key)
            initial = self.routing.nearest(record_key, 256)
            known_keys = dict(self._keys)
        if local is not None:
            result.found = True
            result.record = local
            result.elapsed_ms = (time.perf_counter() - started) * 1000
            return result
        candidates = {c.node_id: c for c in initial}
        queried: set[bytes] = set()
        for _ in range(max_rounds):
            available = [c for c in candidates.values() if c.node_id not in queried]
            if not available:
                break
            available.sort(key=lambda c: (xor_distance(c.node_id, record_key), c.node_id))
            selected = available[:self.alpha]
            queried.update(c.node_id for c in selected)
            result.iterations += 1
            result.rpc_count += len(selected)
            result.queried_by_round.append([c.short_id for c in selected])
            with ThreadPoolExecutor(max_workers=self.alpha) as pool:
                futures = {pool.submit(self._find_value, c, known_keys.get(c.node_id), record_key): c
                           for c in selected}
                for future in as_completed(futures):
                    peer = futures[future]
                    try:
                        record, neighbors = future.result()
                        if record is not None:
                            result.found = True
                            # Если несколько хранителей отвечают разными версиями, выбираем старшую.
                            if result.record is None or record['sequence_number'] > result.record['sequence_number']:
                                result.record = record
                        for contact, key in neighbors:
                            if contact.node_id == self.identity.node_id:
                                continue
                            previous_key = known_keys.get(contact.node_id)
                            if previous_key is not None and previous_key != key:
                                raise ValueError('Противоречащий ключ контакта')
                            if contact.node_id not in candidates:
                                candidates[contact.node_id] = contact
                                known_keys[contact.node_id] = key
                    except (OSError, ConnectionError, ValueError) as exc:
                        result.errors.append(f'{peer.short_id}: {type(exc).__name__}: {exc}')
            if result.found:
                break
        result.elapsed_ms = (time.perf_counter() - started) * 1000
        return result

    def lookup_node(self, target_id: bytes, *, max_rounds: int = 20) -> LookupResult:
        """Итеративный поиск с максимум ALPHA=3 параллельными RPC в раунде.

        Завершение: достигнута цель, кандидаты закончились или max_rounds.
        Контакт, услышанный от соседа, проверяется при обращении к нему.
        """
        validate_node_id(target_id)
        begin = time.perf_counter()
        result = LookupResult(target=target_id.hex())
        with self._lock:
            initial = self.routing.nearest(target_id, 256)
            known_keys = dict(self._keys)
        candidates = {c.node_id: c for c in initial}
        queried: set[bytes] = set()
        verified_target: Contact | None = None
        for _ in range(max_rounds):
            available = [c for c in candidates.values() if c.node_id not in queried]
            if not available:
                break
            available.sort(key=lambda c: (xor_distance(c.node_id, target_id), c.node_id))
            selected = available[:self.alpha]
            queried.update(c.node_id for c in selected)
            result.iterations += 1
            result.rpc_count += len(selected)
            result.queried_by_round.append([c.short_id for c in selected])
            with ThreadPoolExecutor(max_workers=self.alpha) as pool:
                jobs = {pool.submit(self._find_node, c, known_keys.get(c.node_id), target_id): c
                        for c in selected}
                for future in as_completed(jobs):
                    peer = jobs[future]
                    try:
                        neighbors = future.result()
                        # Успешный подписанный ответ подтверждает присутствие адресата.
                        if peer.node_id == target_id:
                            verified_target = peer
                        with self._lock:
                            for n, public_key in neighbors:
                                if n.node_id == self.identity.node_id:
                                    continue
                                if n.node_id not in candidates:
                                    candidates[n.node_id] = n
                                    known_keys[n.node_id] = public_key
                                elif known_keys.get(n.node_id) not in (None, public_key):
                                    raise ValueError('Противоречащий ключ нового контакта')
                    except (OSError, ConnectionError, ValueError) as exc:
                        result.errors.append(f'{peer.short_id}: {type(exc).__name__}: {exc}')
            if verified_target is not None:
                break
        result.found = verified_target is not None
        if verified_target is not None:
            result.result_host = verified_target.host
            result.result_port = verified_target.port
        result.elapsed_ms = (time.perf_counter() - begin) * 1000
        return result

    def join(self, bootstrap_peers: list[tuple[str, int]]) -> dict:
        """PING seed-адресов и self-lookup без глобального реестра.

        Для собственного ID found=False нормально: self-lookup нужен для
        обнаружения других контактов, а не для поиска собственного сокета.
        """
        if not self._server:
            raise RuntimeError('Сначала запустите узел методом start()')
        if not bootstrap_peers:
            raise ValueError('join требует хотя бы один bootstrap-адрес')
        before = self.routing.size()
        successes = []
        failures = []
        for seed in bootstrap_peers:
            host, port = seed[:2]
            try:
                if self.tls_enabled:
                    if len(seed) != 4:
                        raise ValueError('TLS join ожидает (host, port, NodeID, public_key)')
                    peer = self.bootstrap((host, port), expected_node_id=seed[2],
                                          expected_public_key=seed[3])
                else:
                    peer = self.bootstrap((host, port))
                successes.append(peer.short_id)
            except (OSError, ConnectionError, ValueError) as exc:
                failures.append(f'{host}:{port} — {type(exc).__name__}: {exc}')
        if not successes:
            raise ConnectionError('Не удалось подключиться ни к одному seed-узлу: ' + '; '.join(failures))
        discovery = self.lookup_node(self.identity.node_id)
        return {
            'seeds_connected': successes,
            'seeds_failed': failures,
            'contacts_before': before,
            'contacts_after': self.routing.size(),
            'self_lookup_rpc': discovery.rpc_count,
            'self_lookup_iterations': discovery.iterations,
            'self_lookup_errors': discovery.errors,
        }

    def refresh_once(self, bucket_limit: int = 2) -> dict:
        """Искать случайную цель из XOR-диапазона непустого bucket.

        Один вызов проходит не более bucket_limit buckets по очереди.
        Следующий вызов продолжает с новой позиции. Пустые buckets
        пропускаем: для первого учебного пилота этого достаточно.
        """
        if not isinstance(bucket_limit, int) or isinstance(bucket_limit, bool) or bucket_limit < 1:
            raise ValueError('bucket_limit должен быть положительным целым')
        with self._lock:
            nonempty = sorted(i for i, peers in self.routing.bucket_contents().items() if peers)
            if not nonempty:
                self._refresh_runs += 1
                return {'buckets': [], 'total_rpc': 0, 'errors': []}
            count = min(bucket_limit, len(nonempty))
            selected = [nonempty[(self._refresh_cursor + j) % len(nonempty)] for j in range(count)]
            self._refresh_cursor = (self._refresh_cursor + count) % len(nonempty)
        samples = []
        total_rpc = 0
        errors = []
        own_int = int.from_bytes(self.identity.node_id, 'big')
        for index in selected:
            # У цели старший отличающийся бит точно равен index.
            mask = (1 << index) | secrets.randbits(index)
            target = (own_int ^ mask).to_bytes(32, 'big')
            assert bucket_index(self.identity.node_id, target) == index
            res = self.lookup_node(target)
            total_rpc += res.rpc_count
            errors.extend(res.errors)
            samples.append({'bucket': index, 'target': target.hex(),
                            'rpc_count': res.rpc_count, 'iterations': res.iterations,
                            'errors': res.errors})
        with self._lock:
            self._refresh_runs += 1
        return {'buckets': samples, 'total_rpc': total_rpc, 'errors': errors}

    @property
    def refresh_runs(self) -> int:
        with self._lock:
            return self._refresh_runs

    def start_periodic_refresh(self, interval_seconds: float = 60.0,
                               bucket_limit: int = 2) -> None:
        """Фоновый refresh для учебного пилота; параметры задаёт вызывающий код."""
        if not isinstance(interval_seconds, (int, float)) or isinstance(interval_seconds, bool) or not math.isfinite(interval_seconds) or interval_seconds <= 0:
            raise ValueError('interval_seconds должен быть положительным числом')
        if not isinstance(bucket_limit, int) or isinstance(bucket_limit, bool) or bucket_limit < 1:
            raise ValueError('bucket_limit должен быть положительным целым')
        if self._server is None:
            raise RuntimeError('Сначала запустите узел')
        if self._refresh_thread and self._refresh_thread.is_alive():
            raise RuntimeError('Периодический refresh уже запущен')
        self._refresh_stop.clear()

        def worker():
            while not self._refresh_stop.wait(interval_seconds):
                try:
                    self.refresh_once(bucket_limit=bucket_limit)
                except Exception as exc:
                    # Фоновой цикл не должен внезапно умирать из-за одного RPC.
                    with self._lock:
                        self._refresh_errors.append(f'{type(exc).__name__}: {exc}')

        self._refresh_thread = threading.Thread(
            target=worker, name=f'Refresh-{self.name}', daemon=True)
        self._refresh_thread.start()

    def stop_periodic_refresh(self) -> None:
        self._refresh_stop.set()
        worker = self._refresh_thread
        if worker is not None and worker is not threading.current_thread():
            worker.join(timeout=max(2.0, self.timeout * 4))
        self._refresh_thread = None

    def replay_statistics(self) -> dict:
        """Security counters for accepted/blocked authenticated RPC IDs."""
        return self._replay_guard.statistics()

    def tls_statistics(self) -> dict:
        """Only non-secret counters for demonstration and experiment logs."""
        with self._lock:
            return {'tls_enabled': self.tls_enabled,
                    'inbound_tls13': self._tls_accepted,
                    'outbound_tls13': self._tls_outbound}

    def table_snapshot(self) -> dict[int, list[str]]:
        with self._lock:
            return {i: [c.short_id for c in contacts]
                    for i, contacts in self.routing.bucket_contents().items()}
