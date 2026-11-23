"""Точка входа: отдельный процесс = отдельный узел."""
import argparse
import json
import threading
from pathlib import Path
from transport import listen, send_ping


def main():
    parser = argparse.ArgumentParser(description='Учебный P2P-узел, этап 1')
    parser.add_argument('--config', required=True, help='Путь к JSON-конфигурации узла')
    args = parser.parse_args()
    config = json.loads(Path(args.config).read_text(encoding='utf-8'))

    stop = threading.Event()
    thread = threading.Thread(target=listen, args=(config, stop), daemon=True)
    thread.start()
    print("Команды: ping ПОРТ (например: ping 5002), exit")
    try:
        while True:
            command = input(f"[{config['node_name']}] > ").strip().lower()
            if command == 'exit':
                break
            if command.startswith('ping '):
                try:
                    port = int(command.split()[1])
                    send_ping(config, port)
                except (ValueError, OSError, KeyError, IndexError) as exc:
                    print('Ошибка отправки:', exc)
            elif command:
                print('Неизвестная команда. Используй: ping ПОРТ или exit')
    except (KeyboardInterrupt, EOFError):
        pass
    finally:
        stop.set()
        thread.join(timeout=1)
        print(f"Узел {config['node_name']} остановлен")


if __name__ == '__main__':
    main()
