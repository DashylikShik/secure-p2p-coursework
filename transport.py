"""TCP-соединения учебного узла: сервер и отправка PING."""
import socket
import threading
import uuid
from protocol import PING, PONG, read_frame, make_frame


def options(config):
    return {'version': config['protocol_version'],
            'max_payload': config['max_frame_payload']}


def check_pong(frame, expected_request_id):
    """Сопоставить ответ с отправленным запросом."""
    if frame['type'] != PONG or frame['request_id'] != expected_request_id:
        raise ValueError('Ответ не соответствует отправленному PING')


def handle_client(conn, addr, config):
    with conn:
        conn.settimeout(config['socket_timeout'])
        try:
            frame = read_frame(conn, **options(config))
            if frame['type'] != PING:
                raise ValueError('На этом этапе сервер ожидает PING')
            print(f"\n[{config['node_name']}] Получен PING от {addr}: {frame['payload']}", flush=True)
            reply = make_frame(PONG,
                               {'from': config['node_name'], 'text': 'Я на связи!'},
                               request_id=frame['request_id'], **options(config))
            conn.sendall(reply)
        except (ValueError, ConnectionError, OSError) as exc:
            print(f"\n[{config['node_name']}] Ошибка соединения {addr}: {exc}", flush=True)


def listen(config, stop_event):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((config['host'], config['port']))
        server.listen()
        server.settimeout(0.5)
        print(f"[{config['node_name']}] Слушаю {config['host']}:{config['port']}", flush=True)
        while not stop_event.is_set():
            try:
                conn, addr = server.accept()
            except socket.timeout:
                continue
            threading.Thread(target=handle_client, args=(conn, addr, config), daemon=True).start()


def send_ping(config, target_port):
    target = (config['host'], target_port)
    request_id = uuid.uuid4().bytes
    frame = make_frame(PING,
                       {'from': config['node_name'], 'text': 'Привет!'},
                       request_id=request_id, **options(config))
    with socket.create_connection(target, timeout=config['socket_timeout']) as conn:
        conn.settimeout(config['socket_timeout'])
        conn.sendall(frame)
        answer = read_frame(conn, **options(config))
        check_pong(answer, request_id)
        print(f"[{config['node_name']}] Получен PONG от {answer['payload']['from']}: "
              f"{answer['payload']['text']}")
