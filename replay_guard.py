"""Ограниченный in-memory anti-replay журнал подписанных TLS RPC.

Защищает действия в текущем процессе узла; не сохраняется после перезапуска.
Не заменяет встроенную защиту TLS от повторов сетевых записей.
"""
from __future__ import annotations

from collections import OrderedDict
import threading
import time


class ReplayGuard:
    """Дедупликация по (NodeID, message_id) между разными TLS-сессиями."""

    def __init__(self, *, max_entries: int = 4096, window_seconds: float = 3600.0):
        if type(max_entries) is not int or max_entries < 1:
            raise ValueError('max_entries должен быть положительным целым')
        if not isinstance(window_seconds, (int, float)) or not 0 < window_seconds < float('inf'):
            raise ValueError('window_seconds должен быть конечным положительным числом')
        self.max_entries = max_entries
        self.window_seconds = float(window_seconds)
        self._entries: OrderedDict[tuple[bytes, bytes], tuple[bytes, float]] = OrderedDict()
        self._lock = threading.Lock()
        self._accepted = 0
        self._rejected = 0

    def check_and_mark(self, node_id: bytes, session_id: bytes, message_id: bytes) -> None:
        for label, value, length in [('node_id',node_id,32), ('session_id',session_id,16), ('message_id',message_id,16)]:
            if type(value) is not bytes or len(value) != length:
                raise ValueError(f'{label}: неверный размер')
        now = time.monotonic()
        key = (node_id, message_id)
        with self._lock:
            # First entries are oldest (insertion-order), never refresh duplicates.
            while self._entries and next(iter(self._entries.values()))[1] <= now - self.window_seconds:
                self._entries.popitem(last=False)
            if key in self._entries:
                self._rejected += 1
                raise ValueError('Replay: повтор message_id от того же NodeID')
            if len(self._entries) >= self.max_entries:
                # Fail closed under overload: do not forget unexpired IDs,
                # which would silently allow an old signed request to execute.
                self._rejected += 1
                raise ValueError('Replay: журнал переполнен; запрос отклонён')
            self._entries[key] = (session_id, now)
            self._accepted += 1

    def statistics(self) -> dict:
        with self._lock:
            return {'accepted': self._accepted, 'rejected': self._rejected,
                    'cached_message_ids': len(self._entries),
                    'window_seconds': self.window_seconds,
                    'max_entries': self.max_entries}
