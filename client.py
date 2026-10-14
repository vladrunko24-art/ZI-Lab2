import socket
import struct
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
from crypto_v8 import pack_message, try_unpack_message

PORT = 7700


class SecureClientGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Клієнт доступу до захищених даних (Варіант 8)")
        self.root.geometry("520x460")
        self.root.minsize(480, 420)

        self.sock = None
        self.current_user = None
        self.role = None
        self.failed_attempts = 0
        self.server_ip = "127.0.0.1"

        self.root.protocol("WM_DELETE_WINDOW", self.on_close_app)

        self.create_styles()
        self.show_connection_screen()

    def create_styles(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TButton", font=("Arial", 10), padding=5)
        style.configure("TLabel", font=("Arial", 10))
        style.configure("Header.TLabel", font=("Arial", 13, "bold"))

    def clear_screen(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def on_close_app(self):
        if self.sock:
            try:
                self.sock.sendall(pack_message("LOGOUT"))
            except Exception:
                pass
            finally:
                self.sock.close()
        self.root.destroy()


    def discover_server_ip(self) -> str:
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        udp.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        udp.settimeout(1.2)

        for bcast in ("255.255.255.255", "127.0.0.1"):
            try:
                udp.sendto(b"DISCOVER_SRV_7700", (bcast, PORT))
                data, addr = udp.recvfrom(1024)
                if data == b"SERVER_ACK_7700":
                    udp.close()
                    return addr[0]
            except (socket.timeout, OSError):
                continue
        udp.close()
        return "127.0.0.1"

    def send_cmd(self, msg: str) -> str:
        if not self.sock:
            raise ConnectionError("З'єднання з сервером відсутнє")
        try:
            self.sock.sendall(pack_message(msg))
            header = self.sock.recv(8)
            if not header or len(header) < 8:
                raise ConnectionResetError("Сервер розірвав з'єднання")

            payload_len, _ = struct.unpack("!II", header)
            payload = b""
            while len(payload) < payload_len:
                chunk = self.sock.recv(payload_len - len(payload))
                if not chunk:
                    break
                payload += chunk

            res = try_unpack_message(header + payload)
            if res is None:
                raise ValueError("Порушено цілісність даних (хеш не зійшовся)")
            return res
        except (socket.error, OSError) as e:
            raise ConnectionError(f"Мережева помилка: {e}")


    def show_connection_screen(self):
        self.clear_screen()

        frame = ttk.Frame(self.root, padding=25)
        frame.pack(expand=True, fill="both")

        ttk.Label(frame, text="Підключення до сервера", style="Header.TLabel").pack(pady=10)

        ip_frame = ttk.Frame(frame)
        ip_frame.pack(pady=10)
        ttk.Label(ip_frame, text="IP сервера: ").grid(row=0, column=0, padx=5, sticky="w")
        self.ip_entry = ttk.Entry(ip_frame, width=20)
        self.ip_entry.insert(0, self.server_ip)
        self.ip_entry.grid(row=0, column=1, padx=5)

        btn_box = ttk.Frame(frame)
        btn_box.pack(pady=15)

        ttk.Button(btn_box, text="Автопошук (UDP)", command=self.on_udp_discover).grid(row=0, column=0, padx=5)
        ttk.Button(btn_box, text="Підключитися", command=self.on_connect).grid(row=0, column=1, padx=5)
        ttk.Button(btn_box, text="Довідка", command=self.show_help).grid(row=0, column=2, padx=5)

        self.conn_status = ttk.Label(frame, text="", foreground="blue")
        self.conn_status.pack(pady=5)

    def on_udp_discover(self):
        self.conn_status.config(text="Пошук через broadcast...")
        self.root.update()
        found_ip = self.discover_server_ip()
        self.ip_entry.delete(0, tk.END)
        self.ip_entry.insert(0, found_ip)
        self.conn_status.config(text=f"Знайдено IP: {found_ip}")

    def on_connect(self):
        ip = self.ip_entry.get().strip()
        if not ip:
            messagebox.showwarning("Увага", "Введіть коректну IP-адресу.")
            return

        try:
            if self.sock:
                self.sock.close()
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(5.0)
            self.sock.connect((ip, PORT))
            self.sock.settimeout(None)
            self.server_ip = ip
            self.show_login_screen()
        except Exception as e:
            messagebox.showerror("Помилка підключення", f"Не вдалося з'єднатися з {ip}:{PORT}\n\nДеталі: {e}")


    def show_login_screen(self):
        self.clear_screen()

        frame = ttk.Frame(self.root, padding=25)
        frame.pack(expand=True, fill="both")

        status_lbl = ttk.Label(frame, text=f"З'єднання активне: {self.server_ip}:{PORT}", foreground="green")
        status_lbl.pack(pady=2)

        ttk.Label(frame, text="Авторизація в системі", style="Header.TLabel").pack(pady=10)

        form = ttk.Frame(frame)
        form.pack(pady=15)

        ttk.Label(form, text="Логін:").grid(row=0, column=0, sticky="w", pady=5)
        self.login_entry = ttk.Entry(form, width=25)
        self.login_entry.grid(row=0, column=1, pady=5)
        self.login_entry.focus()

        ttk.Label(form, text="Пароль:").grid(row=1, column=0, sticky="w", pady=5)
        self.pass_entry = ttk.Entry(form, width=25, show="*")
        self.pass_entry.grid(row=1, column=1, pady=5)

        btn_box = ttk.Frame(frame)
        btn_box.pack(pady=15)

        ttk.Button(btn_box, text="Увійти", command=self.on_login).grid(row=0, column=0, padx=5)
        ttk.Button(btn_box, text="Довідка", command=self.show_help).grid(row=0, column=1, padx=5)
        ttk.Button(btn_box, text="Змінити сервер", command=self.disconnect_and_reconnect).grid(row=0, column=2, padx=5)

    def on_login(self):
        login = self.login_entry.get().strip()
        pwd = self.pass_entry.get()

        if not login or not pwd:
            messagebox.showwarning("Помилка", "Будь ласка, заповніть логін і пароль.")
            return

        try:
            resp = self.send_cmd(f"LOGIN|{login}|{pwd}")
            parts = resp.split("|")
            status = parts[0]

            if status == "SUCCESS":
                self.current_user = login
                self.role = parts[1]
                is_first = parts[2] == "1"
                self.failed_attempts = 0

                if is_first:
                    messagebox.showinfo("Перший вхід", "Це ваш перший вхід. Необхідно встановити та підтвердити новий пароль!")
                    self.prompt_change_password(is_forced=True)

                self.show_main_dashboard()

            elif status == "DISCONNECT":
                messagebox.showerror("Блокування", parts[1])
                if self.sock:
                    self.sock.close()
                    self.sock = None
                self.show_connection_screen()

            else:
                self.failed_attempts += 1
                err_msg = parts[1] if len(parts) > 1 else resp
                messagebox.showerror("Помилка автентифікації", err_msg)
                if self.failed_attempts >= 3:
                    messagebox.showerror("Вихід", "Перевищено ліміт 3 спроб введення пароля. З'єднання закрито.")
                    if self.sock:
                        self.sock.close()
                        self.sock = None
                    self.show_connection_screen()

        except Exception as e:
            messagebox.showerror("Помилка зв'язку", str(e))
            if self.sock:
                self.sock.close()
                self.sock = None
            self.show_connection_screen()


    def show_main_dashboard(self):
        self.clear_screen()

        frame = ttk.Frame(self.root, padding=20)
        frame.pack(expand=True, fill="both")

        header_text = f"Користувач: {self.current_user} | Роль: {self.role}"
        ttk.Label(frame, text=header_text, style="Header.TLabel").pack(pady=5)

        ttk.Separator(frame, orient="horizontal").pack(fill="x", pady=10)

        btn_box = ttk.Frame(frame)
        btn_box.pack(pady=10)

        if self.role == "ADMIN":
            ttk.Button(btn_box, text="1. Змінити пароль ADMIN", width=30,
                       command=lambda: self.prompt_change_password(False)).pack(pady=4)
            ttk.Button(btn_box, text="2. Додати користувача", width=30,
                       command=self.admin_add_user).pack(pady=4)
            ttk.Button(btn_box, text="3. Заблокувати користувача", width=30,
                       command=self.admin_block_user).pack(pady=4)
        else:
            ttk.Button(btn_box, text="1. Отримати документ", width=30,
                       command=self.user_get_doc).pack(pady=4)
            ttk.Button(btn_box, text="2. Змінити власний пароль", width=30,
                       command=lambda: self.prompt_change_password(False)).pack(pady=4)

        ttk.Button(btn_box, text="Довідка про програму", width=30,
                   command=self.show_help).pack(pady=4)
        ttk.Button(btn_box, text="Завершити сесію (Змінити користувача)", width=30,
                   command=self.logout).pack(pady=10)

        self.output_txt = tk.Text(frame, height=7, width=55, state="disabled")
        self.output_txt.pack(pady=10)

    def log_result(self, message: str):
        self.output_txt.config(state="normal")
        self.output_txt.delete("1.0", tk.END)
        self.output_txt.insert(tk.END, message)
        self.output_txt.config(state="disabled")


    def user_get_doc(self):
        try:
            resp = self.send_cmd("GET_DOC")
            parts = resp.split("|", 1)
            self.log_result(parts[1] if len(parts) > 1 else resp)
        except Exception as e:
            messagebox.showerror("Помилка", str(e))

    def admin_add_user(self):
        dialog = UserCreationDialog(self.root)
        self.root.wait_window(dialog.top)

        if dialog.result:
            u, p = dialog.result
            try:
                resp = self.send_cmd(f"ADD_USER|{u}|{p}")
                parts = resp.split("|", 1)
                messagebox.showinfo("Результат", parts[1] if len(parts) > 1 else resp)
            except Exception as e:
                messagebox.showerror("Помилка", str(e))

    def admin_block_user(self):
        target = simpledialog.askstring("Блокування", "Введіть ім'я користувача для блокування:", parent=self.root)
        if target:
            try:
                resp = self.send_cmd(f"BLOCK_USER|{target.strip()}")
                parts = resp.split("|", 1)
                messagebox.showinfo("Результат", parts[1] if len(parts) > 1 else resp)
            except Exception as e:
                messagebox.showerror("Помилка", str(e))

    def prompt_change_password(self, is_forced: bool):
        dialog = PasswordChangeDialog(self.root, is_forced)
        self.root.wait_window(dialog.top)

        if dialog.new_password:
            try:
                resp = self.send_cmd(f"CHANGE_PASS|{dialog.new_password}")
                parts = resp.split("|", 1)
                messagebox.showinfo("Пароль", parts[1] if len(parts) > 1 else resp)
            except Exception as e:
                messagebox.showerror("Помилка", str(e))

    def logout(self):
        try:
            self.send_cmd("LOGOUT")
        except Exception:
            pass

        self.current_user = None
        self.role = None
        self.failed_attempts = 0
        # Повертаємо вікно авторизації БЕЗ повторного підключення до сервера
        self.show_login_screen()

    def disconnect_and_reconnect(self):
        if self.sock:
            try:
                self.sock.sendall(pack_message("LOGOUT"))
            except Exception:
                pass
            self.sock.close()
            self.sock = None
        self.show_connection_screen()

    def show_help(self):
        help_text = (
            "====================== ДОВІДКА ======================\n"
            "Лабораторна робота №2: Розробка клієнт-сервера видаленого\n"
            "доступу до захищених даних.\n\n"
            "Варіант 8:\n"
            "  - Алгоритм шифрування: Шифр підстановки на 8 символів\n"
            "  - Хеш-функція: 2-й раунд SHA (SHA-1 Round 2)\n"
            "  - Порт підключення: 7700 (UDP / TCP)\n\n"
            "Автор: Рунько Владислав Сергійович, ЗК-51мн\n"
            "Можливості: Одноразове підключення до сервера, швидка зміна\n"
            "користувачів без розриву каналу зв'язку, маскування '*', ролі\n"
            "ADMIN / USER, блокування після 3 невірних спроб, обов'язкова\n"
            "зміна пароля при першому вході."
        )
        messagebox.showinfo("Довідка про програму", help_text)



class PasswordChangeDialog:
    def __init__(self, parent, is_forced=False):
        self.top = tk.Toplevel(parent)
        self.top.title("Зміна пароля")
        self.top.geometry("340x220")
        self.top.grab_set()
        self.new_password = None

        if is_forced:
            self.top.protocol("WM_DELETE_WINDOW", lambda: None)

        ttk.Label(self.top, text="Введіть новий пароль:").pack(pady=5)
        self.p1_entry = ttk.Entry(self.top, show="*", width=25)
        self.p1_entry.pack(pady=5)

        ttk.Label(self.top, text="Підтвердіть новий пароль:").pack(pady=5)
        self.p2_entry = ttk.Entry(self.top, show="*", width=25)
        self.p2_entry.pack(pady=5)

        ttk.Button(self.top, text="Зберегти", command=self.on_save).pack(pady=12)

    def on_save(self):
        p1 = self.p1_entry.get()
        p2 = self.p2_entry.get()

        if not p1 or not p2:
            messagebox.showwarning("Помилка", "Пароль не може бути порожнім.", parent=self.top)
            return

        if p1 != p2:
            messagebox.showerror("Помилка", "Введені паролі не співпадають!", parent=self.top)
            return

        self.new_password = p1
        self.top.destroy()


class UserCreationDialog:
    def __init__(self, parent):
        self.top = tk.Toplevel(parent)
        self.top.title("Створення користувача")
        self.top.geometry("340x220")
        self.top.grab_set()
        self.result = None

        ttk.Label(self.top, text="Логін нового користувача:").pack(pady=5)
        self.u_entry = ttk.Entry(self.top, width=25)
        self.u_entry.pack(pady=5)

        ttk.Label(self.top, text="Тимчасовий пароль:").pack(pady=5)
        self.p_entry = ttk.Entry(self.top, show="*", width=25)
        self.p_entry.pack(pady=5)

        ttk.Button(self.top, text="Додати", command=self.on_create).pack(pady=12)

    def on_create(self):
        u = self.u_entry.get().strip()
        p = self.p_entry.get()
        if not u or not p:
            messagebox.showwarning("Помилка", "Заповніть усі поля.", parent=self.top)
            return
        self.result = (u, p)
        self.top.destroy()


if __name__ == "__main__":
    tk_root = tk.Tk()
    app = SecureClientGUI(tk_root)
    tk_root.mainloop()