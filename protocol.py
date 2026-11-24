"""Формат кадров учебного P2P-протокола (этап 1)."""
import json
import struct
import uuid

HEADER = struct.Struct('!BBH16sI')  # 1+1+2+16+4 = 24 байта
PING = 1
PONG = 2
FIND_NODE_REQUEST = 3
FIND_NODE_RESPONSE = 4
STORE_REQUEST = 5
STORE_RESPONSE = 6
FIND_VALUE_REQUEST = 7
FIND_VALUE_RESPONSE = 8
ERROR = 255
KNOWN_TYPES = {PING, PONG, FIND_NODE_REQUEST, FIND_NODE_RESPONSE,
               STORE_REQUEST, STORE_RESPONSE, FIND_VALUE_REQUEST, FIND_VALUE_RESPONSE, ERROR}


def make_frame(message_type, payload, *, request_id=None, version=1, max_payload=65536):
    """Преобразовать словарь payload в кадр: заголовок + JSON-байты."""
    if message_type not in KNOWN_TYPES:
        raise ValueError('Неизвестный тип сообщения')
    if request_id is None:
        request_id = uuid.uuid4().bytes
    if not isinstance(request_id, bytes) or len(request_id) != 16:
        raise ValueError('request_id должен содержать 16 байт')
    data = json.dumps(payload, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    if len(data) > max_payload:
        raise ValueError('Превышена максимальная длина payload')
    header = HEADER.pack(version, message_type, 0, request_id, len(data))
    return header + data


def recv_exact(sock, count):
    """Прочитать ровно count байт: один recv() НЕ гарантирует весь кадр."""
    chunks = []
    remaining = count
    while remaining:
        part = sock.recv(remaining)
        if not part:
            raise ConnectionError('Соединение закрыто до окончания кадра')
        chunks.append(part)
        remaining -= len(part)
    return b''.join(chunks)


def read_frame(sock, *, version=1, max_payload=65536):
    """Прочитать и проверить один кадр из TCP-потока."""
    header = recv_exact(sock, HEADER.size)
    received_version, message_type, flags, request_id, length = HEADER.unpack(header)
    if received_version != version:
        raise ValueError('Неподдерживаемая версия протокола')
    if message_type not in KNOWN_TYPES:
        raise ValueError('Неизвестный тип кадра')
    if flags != 0:
        raise ValueError('Неподдерживаемые флаги кадра')
    if length > max_payload:  # проверяем ДО чтения payload
        raise ValueError('payload_length превышает установленный лимит')
    raw = recv_exact(sock, length)
    try:
        payload = json.loads(raw.decode('utf-8'))
    except (ValueError, UnicodeError) as exc:
        raise ValueError('Некорректный JSON payload') from exc
    if not isinstance(payload, dict):
        raise ValueError('payload должен быть JSON-объектом')
    return {'type': message_type, 'request_id': request_id, 'payload': payload}
