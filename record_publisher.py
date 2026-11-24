"""Периодическая публикация собственных подписанных NodeRecord через DHT.

Этап 3.4: владелец выпускает новую signed NodeRecord с увеличенным
sequence_number и отправляет её на R=3 хранителей. При недостаточном числе
подтверждений повторяет ТОТ ЖЕ подписанный record до срока его действия.
Учебный стенд работает на localhost; это не TLS/персистентное хранилище.
"""
from __future__ import annotations

import json
import math
import os
import threading
import time
import uuid
from copy import deepcopy
from pathlib import Path
from typing import Callable

from dht_records import TTL_MAX, TTL_MIN, make_node_record, verify_node_record


class RecordPublisher:
    """Обслуживание только собственной записи узла (владельцем ключа)."""

    def __init__(self, node, *, ttl: int = 180, interval_seconds: float = 60.0,
                 initial_sequence: int = 1, clock: Callable[[], float] = time.time,
                 sequence_path: str | Path | None = None):
        if type(ttl) is not int or not (TTL_MIN <= ttl <= TTL_MAX):
            raise ValueError('TTL должен быть целым числом в пределах 120–300 секунд')
        if (isinstance(interval_seconds, bool) or not isinstance(interval_seconds, (int, float))
                or not math.isfinite(interval_seconds) or interval_seconds <= 0
                or interval_seconds > ttl / 2):
            raise ValueError('Интервал republish должен быть > 0 и <= TTL/2')
        if type(initial_sequence) is not int or initial_sequence < 1:
            raise ValueError('initial_sequence должен быть положительным целым')
        if not callable(clock):
            raise TypeError('clock должен быть вызываемой функцией')
        self.node = node
        self.ttl = ttl
        self.interval_seconds = float(interval_seconds)
        self._clock = clock
        self._sequence_path = Path(sequence_path) if sequence_path is not None else None
        self._next_sequence = initial_sequence
        if self._sequence_path is not None and self._sequence_path.exists():
            try:
                state = json.loads(self._sequence_path.read_text(encoding='utf-8'))
            except (OSError, json.JSONDecodeError) as exc:
                raise ValueError('Повреждено состояние счётчика republish') from exc
            if (not isinstance(state, dict) or state.get('node_id') != node.identity.node_id.hex()
                    or type(state.get('next_sequence')) is not int
                    or state['next_sequence'] < 1):
                raise ValueError('Состояние sequence_number не соответствует узлу')
            self._next_sequence = max(initial_sequence, state['next_sequence'])
        self._pending: dict | None = None
        self._mutex = threading.RLock()
        self._stopping = threading.Event()
        self._thread: threading.Thread | None = None
        self._history: list[dict] = []
        self._automatic_runs = 0

    @property
    def automatic_runs(self) -> int:
        with self._mutex:
            return self._automatic_runs

    def history(self) -> list[dict]:
        with self._mutex:
            return deepcopy(self._history)

    def _add_history(self, row: dict) -> None:
        self._history.append(deepcopy(row))
        self._history = self._history[-100:]

    def _save_next_sequence(self) -> None:
        """Резервировать следующий номер атомарно, не публикуя секретов."""
        if self._sequence_path is None:
            return
        target = self._sequence_path
        target.parent.mkdir(parents=True, exist_ok=True)
        scratch = target.with_name(target.name + '.' + uuid.uuid4().hex + '.tmp')
        try:
            scratch.write_text(json.dumps({
                'node_id': self.node.identity.node_id.hex(),
                'next_sequence': self._next_sequence,
            }, ensure_ascii=False), encoding='utf-8')
            os.replace(scratch, target)
        finally:
            scratch.unlink(missing_ok=True)

    def publish_once(self) -> dict:
        """Одна попытка публикации. Ошибки сети учитываются как failed.

        Частичный STORE может уже достигнуть одного узла, поэтому при
        повторной попытке используем неизменённый pending record.
        """
        with self._mutex:
            if self.node._server is None:
                raise RuntimeError('Прежде чем публиковать запись, запустите DHTNode.start()')
            now = int(self._clock())
            if self._pending is None or now >= self._pending['expires_at']:
                record = make_node_record(
                    self.node.identity,
                    [{'host': self.node.host, 'port': self.node.port}],
                    self._next_sequence, now=now, ttl=self.ttl)
                self._next_sequence += 1
                self._save_next_sequence()
                self._pending = record
                retry = False
            else:
                record = self._pending
                retry = True
            # Проверяем корректность владения, подписи и сроков до RPC.
            verify_node_record(record, now=now)
            try:
                placement = self.node.store_replicated(record)
                summary = placement.as_dict()
                succeeded = bool(placement.succeeded)
                details = {
                    'ack_count': summary['ack_count'],
                    'required_acks': summary['required_acks'],
                    'selected_count': len(summary['selected']),
                    'discovery_rpc': summary['discovery_rpc'],
                }
            except (OSError, ConnectionError, ValueError) as exc:
                succeeded = False
                details = {'ack_count': 0, 'required_acks': 2, 'selected_count': 0,
                           'discovery_rpc': 0, 'error': f'{type(exc).__name__}: {exc}'}
            row = {
                'sequence_number': record['sequence_number'],
                'issued_at': record['issued_at'],
                'expires_at': record['expires_at'],
                'retry_same_record': retry,
                'succeeded': succeeded,
                **details,
            }
            if succeeded:
                self._pending = None
            self._add_history(row)
            return deepcopy(row)

    def start(self) -> None:
        """Включить фоновые публикации; первую вызывают через publish_once()."""
        with self._mutex:
            if self.node._server is None:
                raise RuntimeError('Сначала запустите узел')
            if self._thread is not None and self._thread.is_alive():
                raise RuntimeError('Republish уже запущен')
            self._stopping.clear()
            self._thread = threading.Thread(target=self._worker,
                                            name=f'Republish-{self.node.name}', daemon=True)
            self._thread.start()

    def _worker(self) -> None:
        while not self._stopping.wait(self.interval_seconds):
            try:
                self.publish_once()
            except Exception as exc:
                with self._mutex:
                    self._add_history({'succeeded': False,
                                       'error': f'{type(exc).__name__}: {exc}',
                                       'background_failure': True})
            finally:
                with self._mutex:
                    self._automatic_runs += 1

    def stop(self) -> None:
        self._stopping.set()
        worker = self._thread
        if worker is not None and worker is not threading.current_thread():
            worker.join(timeout=10)
        self._thread = None
