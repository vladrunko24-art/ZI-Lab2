import socket
import struct
import threading
from crypto_v8 import pack_message, try_unpack_message

PORT = 7700

users_db = {
    "ADMIN": {
        "pass": "admin123",
        "blocked": False,
        "first_login": False,
    }
}
db_lock = threading.Lock()


def udp_discovery_worker():
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    except (AttributeError, OSError):
        pass

    try:
        udp_sock.bind(("0.0.0.0", PORT))
    except OSError as err:
        print(f"[UDP Warning] Порт {PORT} зайнятий для UDP: {err}")
        return

    while True:
        try:
            data, addr = udp_sock.recvfrom(1024)
            if data.decode("utf-8", errors="ignore") == "DISCOVER_SRV_7700":
                udp_sock.sendto(b"SERVER_ACK_7700", addr)
        except Exception:
            break


def handle_client(conn: socket.socket, addr):
    current_user = None
    failed_attempts = 0

    def send_enc(msg: str):
        try:
            conn.sendall(pack_message(msg))
        except (socket.error, BrokenPipeError):
            pass

    try:
        while True:
            header = conn.recv(8)
            if not header or len(header) < 8:
                break

            payload_len, _ = struct.unpack("!II", header)
            payload = b""
            while len(payload) < payload_len:
                chunk = conn.recv(payload_len - len(payload))
                if not chunk:
                    break
                payload += chunk

            request = try_unpack_message(header + payload)
            if request is None:
                send_enc("ERR|Помилка цілісності пакету")
                continue

            parts = request.split("|")
            cmd = parts[0]

            if cmd == "LOGIN":
                if len(parts) < 3:
                    send_enc("FAIL|Некоректні параметри запиту")
                    continue
                username, password = parts[1], parts[2]
                with db_lock:
                    if username not in users_db:
                        send_enc("FAIL|Користувача не знайдено")
                        continue

                    user = users_db[username]
                    if user["blocked"]:
                        send_enc("BLOCKED|Цей акаунт заблоковано адміністратором")
                        continue

                    if user["pass"] != password:
                        failed_attempts += 1
                        if failed_attempts >= 3:
                            send_enc("DISCONNECT|Перевищено 3 спроби входу")
                            break
                        send_enc(f"FAIL|Невірний пароль. Залишилось спроб: {3 - failed_attempts}")
                        continue

                    failed_attempts = 0
                    current_user = username
                    role = "ADMIN" if username == "ADMIN" else "USER"
                    first = "1" if user["first_login"] else "0"
                    send_enc(f"SUCCESS|{role}|{first}")

            elif cmd == "CHANGE_PASS":
                if len(parts) < 2:
                    send_enc("ERR|Порожній пароль")
                    continue
                new_pass = parts[1]
                with db_lock:
                    if current_user and current_user in users_db:
                        users_db[current_user]["pass"] = new_pass
                        users_db[current_user]["first_login"] = False
                        send_enc("OK|Пароль успішно оновлено")

            elif cmd == "ADD_USER":
                if current_user == "ADMIN":
                    if len(parts) < 3:
                        send_enc("ERR|Недостатньо параметрів")
                        continue
                    new_u, new_p = parts[1], parts[2]
                    with db_lock:
                        if new_u in users_db:
                            send_enc("ERR|Користувач вже існує")
                        else:
                            users_db[new_u] = {
                                "pass": new_p,
                                "blocked": False,
                                "first_login": True,
                            }
                            send_enc(f"OK|Користувача {new_u} успішно створено")
                else:
                    send_enc("ERR|Недостатньо прав")

            elif cmd == "BLOCK_USER":
                if current_user == "ADMIN":
                    if len(parts) < 2:
                        send_enc("ERR|Вкажіть користувача")
                        continue
                    target = parts[1]
                    with db_lock:
                        if target == "ADMIN":
                            send_enc("ERR|Неможливо заблокувати ADMIN")
                        elif target in users_db:
                            users_db[target]["blocked"] = True
                            send_enc(f"OK|Користувача {target} заблоковано")
                        else:
                            send_enc("ERR|Користувача не знайдено")
                else:
                    send_enc("ERR|Недостатньо прав")

            elif cmd == "GET_DOC":
                if current_user and current_user != "ADMIN":
                    send_enc("DOC|мільйон причин для того, щоб зростати щоб кожен день упевнено іти вперед щоб в серці віру незгасиму мати і будувати власний шлях, вилазити з тенет")
                else:
                    send_enc("ERR|Функція недоступна для цієї ролі")

            elif cmd == "LOGOUT":
                current_user = None
                failed_attempts = 0
                send_enc("OK|LOGOUT_SUCCESS")

    except Exception as err:
        print(f"[Клієнт {addr}] помилка з'єднання: {err}")
    finally:
        conn.close()


def main():
    print(f"[СЕРВЕР] Запуск на порту {PORT} (Варіант 8)...")
    threading.Thread(target=udp_discovery_worker, daemon=True).start()

    tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        tcp_sock.bind(("0.0.0.0", PORT))
        tcp_sock.listen(5)
        print("[СЕРВЕР] Готовий до підключень...")
    except OSError as err:
        print(f"[FATAL] Не вдалося запустити TCP сервер на порту {PORT}: {err}")
        return

    while True:
        try:
            conn, addr = tcp_sock.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
        except KeyboardInterrupt:
            break
        except Exception as err:
            print(f"[Accept Error]: {err}")

    tcp_sock.close()


if __name__ == "__main__":
    main()