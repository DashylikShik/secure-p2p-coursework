"""Этап 3, часть 1: подписанные NodeRecord, TTL и локальное DHT-хранилище.

ВНИМАНИЕ: класс RecordStore пока локален. Это НЕ сетевые STORE/FIND_VALUE,
не репликация и не защита канала TLS. Эти части реализуются позже.
"""
from __future__ import annotations

import hashlib
import json
import time
from copy import deepcopy
from typing import Any

from identity import Identity, verify_node_id, verify_signature

DOMAIN = b'coursework-dht-node-record-v1\x00'
TTL_MIN = 120
TTL_MAX = 300
MAX_RECORD_BYTES = 4096
MAX_ADDRESSES = 4
MAX_CLOCK_SKEW = 60
FIELDS = {'node_id', 'identity_public_key', 'addresses', 'sequence_number',
          'issued_at', 'expires_at', 'signature'}
SIGNED_FIELDS = FIELDS - {'signature'}


class RecordRejected(ValueError):
    """Запись не прошла проверки формата, подписи, срока или версии."""


def _int(value: Any, name: str, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise RecordRejected(f'{name}: требуется целое число >= {minimum}')
    return value


def _hex_bytes(value: Any, count: int, name: str) -> bytes:
    if not isinstance(value, str) or len(value) != 2 * count:
        raise RecordRejected(f'{name}: ожидается {count} байт в hex')
    try:
        raw = bytes.fromhex(value)
    except ValueError as e:
        raise RecordRejected(f'{name}: неправильный hex') from e
    if len(raw) != count:
        raise RecordRejected(f'{name}: неправильная длина')
    return raw


def _address_list(value: Any) -> None:
    if not isinstance(value, list) or not (1 <= len(value) <= MAX_ADDRESSES):
        raise RecordRejected('addresses: от 1 до 4 адресов')
    used: set[tuple[str, int]] = set()
    for addr in value:
        if not isinstance(addr, dict) or set(addr) != {'host', 'port'}:
            raise RecordRejected('addresses: только host и port')
        # Текущий локальный пилот работает только на loopback.
        # При расширении underlay разрешённые адреса будут конфигурируемыми.
        host, port = addr['host'], addr['port']
        if host != '127.0.0.1' or type(port) is not int or not (1 <= port <= 65535):
            raise RecordRejected('addresses: некорректные host/port')
        if (host, port) in used:
            raise RecordRejected('addresses: дубликат')
        used.add((host, port))


def _canonical_bytes(unsigned: dict) -> bytes:
    return json.dumps(unsigned, ensure_ascii=True, sort_keys=True,
                      separators=(',', ':'), allow_nan=False).encode('utf-8')


def record_key(node_id: bytes) -> bytes:
    """Ключ записи упрощённого уровня: SHA-256(b'node:' || NodeID)."""
    if not isinstance(node_id, bytes) or len(node_id) != 32:
        raise RecordRejected('NodeID должен состоять из 32 байт')
    return hashlib.sha256(b'node:' + node_id).digest()


def make_node_record(identity: Identity, addresses: list[dict],
                     sequence_number: int, *, now: int | None = None,
                     ttl: int = 180) -> dict:
    """Подписать запись владельца. Секретный ключ наружу не выходит."""
    issued = int(time.time()) if now is None else _int(now, 'now')
    _int(ttl, 'ttl')
    if not TTL_MIN <= ttl <= TTL_MAX:
        raise RecordRejected('TTL должен быть в пределах 120–300 секунд')
    _int(sequence_number, 'sequence_number', 1)
    _address_list(addresses)
    unsigned = {
        'node_id': identity.node_id.hex(),
        'identity_public_key': identity.public_key_bytes.hex(),
        'addresses': deepcopy(addresses),
        'sequence_number': sequence_number,
        'issued_at': issued,
        'expires_at': issued + ttl,
    }
    signature = identity.sign(DOMAIN + _canonical_bytes(unsigned))
    return {**unsigned, 'signature': signature.hex()}


def verify_node_record(record: dict, *, now: int | None = None) -> bytes:
    """Выполнить все проверки до использования записи, вернуть её DHT-ключ."""
    current = int(time.time()) if now is None else _int(now, 'now')
    if not isinstance(record, dict) or set(record) != FIELDS:
        raise RecordRejected('Неверный состав полей NodeRecord')
    try:
        encoded = _canonical_bytes(record)
    except (TypeError, ValueError) as e:
        raise RecordRejected('Запись не сериализуется') from e
    if len(encoded) > MAX_RECORD_BYTES:
        raise RecordRejected('Слишком большая NodeRecord')
    node_id = _hex_bytes(record['node_id'], 32, 'node_id')
    key = _hex_bytes(record['identity_public_key'], 32, 'identity_public_key')
    signature = _hex_bytes(record['signature'], 64, 'signature')
    if not verify_node_id(node_id, key):
        raise RecordRejected('NodeID не совпадает с открытым ключом')
    _address_list(record['addresses'])
    version = _int(record['sequence_number'], 'sequence_number', 1)
    issued = _int(record['issued_at'], 'issued_at')
    expires = _int(record['expires_at'], 'expires_at')
    if not TTL_MIN <= expires - issued <= TTL_MAX:
        raise RecordRejected('Некорректный TTL')
    if issued > current + MAX_CLOCK_SKEW:
        raise RecordRejected('Дата создания из будущего')
    if current >= expires:
        raise RecordRejected('Истёк срок действия')
    unsigned = {name: record[name] for name in SIGNED_FIELDS}
    if not verify_signature(key, DOMAIN + _canonical_bytes(unsigned), signature):
        raise RecordRejected('Цифровая подпись NodeRecord неверна')
    return record_key(node_id)


class LocalRecordStore:
    """Локальное хранилище с TTL и защитой от отката в текущем процессе.

    ВАЖНО: все поля и highest_sequence только в памяти; после перезапуска
    необходимо сохранять watermark на диск, иначе защита от отката теряется.
    """

    def __init__(self, max_records: int = 256):
        self.max_records = _int(max_records, 'max_records', 1)
        self._records: dict[bytes, dict] = {}
        self._highest: dict[bytes, int] = {}
        self._fingerprint: dict[bytes, bytes] = {}

    def put(self, record: dict, *, now: int | None = None) -> str:
        key = verify_node_record(record, now=now)
        version = record['sequence_number']
        fingerprint = hashlib.sha256(_canonical_bytes(record)).digest()
        last = self._highest.get(key)
        if last is not None:
            if version < last:
                raise RecordRejected('Откат версии sequence_number')
            if version == last:
                if fingerprint == self._fingerprint[key]:
                    return 'duplicate'
                raise RecordRejected('Конфликт: одинаковая версия, разные данные')
        self.purge_expired(now=now)
        if key not in self._records and len(self._records) >= self.max_records:
            raise RecordRejected('Хранилище заполнено')
        self._records[key] = deepcopy(record)
        self._highest[key] = version
        self._fingerprint[key] = fingerprint
        return 'stored' if last is None else 'updated'

    def get(self, key: bytes, *, now: int | None = None) -> dict | None:
        if not isinstance(key, bytes) or len(key) != 32:
            raise RecordRejected('Ключ DHT должен состоять из 32 байт')
        found = self._records.get(key)
        if found is None:
            return None
        try:
            verify_node_record(found, now=now)
        except RecordRejected:
            self._records.pop(key, None)
            return None
        return deepcopy(found)

    def purge_expired(self, *, now: int | None = None) -> int:
        count = 0
        for key in list(self._records):
            if self.get(key, now=now) is None:
                count += 1
        return count

    def __len__(self) -> int:
        return len(self._records)
