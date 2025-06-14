import tkinter as tk
from tkinter import messagebox, filedialog
import json
import os
import subprocess
import shlex
import sys
import tempfile

# --------------------- Cấu hình ---------------------
def get_app_dir():
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))

APP_DIR = get_app_dir()
CONFIG_PATH = os.path.join(APP_DIR, "servers.json")
SERVERS = {}
CURRENT_SERVER = None
FIXED_PASSWORD = '1'

# --------------------- Tải & lưu dữ liệu ---------------------
def load_servers():
    global SERVERS
    if not os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump({}, f)
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
            SERVERS = data if isinstance(data, dict) else {}
    except Exception as e:
        messagebox.showerror("Lỗi", f"Không thể đọc file servers.json: {str(e)}")
        SERVERS = {}

def save_servers():
    try:
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(SERVERS, f, indent=4, ensure_ascii=False)
        return True
    except Exception as e:
        messagebox.showerror("Lỗi", f"Không thể lưu file servers.json: {str(e)}")
        return False

# --------------------- Các hàm xử lý ---------------------
def refresh_server_list():
    server_listbox.delete(0, tk.END)
    for name in SERVERS.keys():
        server_listbox.insert(tk.END, name)

def clear_entries():
    entry_name.delete(0, tk.END)
    entry_ip.delete(0, tk.END)
    entry_user.delete(0, tk.END)
    entry_pem.delete(0, tk.END)
    entry_password.delete(0, tk.END)

def on_server_select(event):
    global CURRENT_SERVER
    selection = server_listbox.curselection()
    if selection:
        name = server_listbox.get(selection[0])
        CURRENT_SERVER = name
        server = SERVERS.get(name, {})
        clear_entries()
        entry_name.insert(0, name)
        entry_ip.insert(0, server.get("ip", ""))
        entry_user.insert(0, server.get("username", ""))
        entry_pem.insert(0, server.get("pem", ""))
        entry_password.insert(0, server.get("password", ""))
    else:
        CURRENT_SERVER = None
        clear_entries()

def add_server():
    name = entry_name.get().strip()
    ip = entry_ip.get().strip()
    user = entry_user.get().strip()
    pem = entry_pem.get().strip()
    password = entry_password.get().strip()

    if not name:
        messagebox.showerror("Lỗi", "Tên server không được để trống")
        return
    if not ip or not user:
        messagebox.showerror("Lỗi", "IP và Username không được để trống")
        return
    if name in SERVERS:
        messagebox.showerror("Lỗi", "Server đã tồn tại")
        return

    SERVERS[name] = {
        "ip": ip,
        "username": user,
        "pem": pem,
        "password": password
    }
    if save_servers():
        refresh_server_list()
        clear_entries()
        messagebox.showinfo("Thành công", f"Đã thêm server '{name}'")

def edit_server():
    global CURRENT_SERVER
    if not CURRENT_SERVER:
        messagebox.showerror("Lỗi", "Chọn server để sửa")
        return

    name = entry_name.get().strip()
    ip = entry_ip.get().strip()
    user = entry_user.get().strip()
    pem = entry_pem.get().strip()
    password = entry_password.get().strip()

    if not name:
        messagebox.showerror("Lỗi", "Tên server không được để trống")
        return
    if not ip or not user:
        messagebox.showerror("Lỗi", "IP và Username không được để trống")
        return

    if name != CURRENT_SERVER and name in SERVERS:
        messagebox.showerror("Lỗi", "Tên server đã tồn tại")
        return

    if name != CURRENT_SERVER:
        SERVERS.pop(CURRENT_SERVER, None)

    SERVERS[name] = {
        "ip": ip,
        "username": user,
        "pem": pem,
        "password": password
    }
    if save_servers():
        refresh_server_list()
        CURRENT_SERVER = name
        messagebox.showinfo("Thành công", f"Đã sửa server '{name}'")


def delete_server():
    global CURRENT_SERVER
    if not CURRENT_SERVER:
        messagebox.showerror("Lỗi", "Chọn server để xóa")
        return
    if messagebox.askyesno("Xác nhận", f"Xóa server '{CURRENT_SERVER}'?"):
        SERVERS.pop(CURRENT_SERVER, None)
        if save_servers():
            refresh_server_list()
            clear_entries()
            messagebox.showinfo("Đã xóa", f"Đã xóa server '{CURRENT_SERVER}'")
            CURRENT_SERVER = None

def import_servers_from_file():
    global SERVERS
    file_path = filedialog.askopenfilename(
        title="Chọn file servers.json để import",
        filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
    )
    if not file_path:
        return

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            if not isinstance(data, dict):
                messagebox.showerror("Lỗi", "File không đúng định dạng servers.json (phải là dict)")
                return
            SERVERS.update(data)
            if save_servers():
                refresh_server_list()
                messagebox.showinfo("Thành công", f"Đã import từ {os.path.basename(file_path)}")
    except Exception as e:
        messagebox.showerror("Lỗi", f"Không thể load file: {str(e)}")

def connect_ssh():
    if not CURRENT_SERVER:
        messagebox.showerror("Lỗi", "Chọn server để kết nối")
        return
    server = SERVERS.get(CURRENT_SERVER)
    ip = server.get("ip", "")
    user = server.get("username", "")
    pem = server.get("pem", "")

    if not ip or not user:
        messagebox.showerror("Lỗi", "Thiếu thông tin kết nối")
        return

    if pem:
        ssh_command = f"ssh -i {shlex.quote(pem)} {shlex.quote(user)}@{shlex.quote(ip)}"
    else:
        ssh_command = f"ssh {shlex.quote(user)}@{shlex.quote(ip)}"

    apple_script = f'''
    tell application "Terminal"
        activate
        do script "{ssh_command}"
    end tell
    '''
    with tempfile.NamedTemporaryFile(mode="w", suffix=".applescript", delete=False) as tmp:
        tmp.write(apple_script)
        tmp_path = tmp.name

    subprocess.run(["osascript", tmp_path])
    os.remove(tmp_path)

# --------------------- Giao diện chính ---------------------
def show_main_app():
    global server_listbox, entry_name, entry_ip, entry_user, entry_pem, entry_password

    login_window.withdraw()
    main_window = tk.Toplevel()
    main_window.title("Quản lý SSH Server")
    main_window.protocol("WM_DELETE_WINDOW", login_window.quit)  # Thoát hoàn toàn

    # Frame danh sách
    frame_list = tk.LabelFrame(main_window, text="Danh sách server")
    frame_list.pack(side=tk.LEFT, padx=10, pady=10, fill=tk.Y)

    server_listbox = tk.Listbox(frame_list, width=30, height=15)
    server_listbox.pack()
    server_listbox.bind("<<ListboxSelect>>", on_server_select)

    # Frame chi tiết
    frame_detail = tk.LabelFrame(main_window, text="Thông tin server")
    frame_detail.pack(side=tk.RIGHT, padx=10, pady=10, fill=tk.BOTH, expand=True)

    # Các entry
    entry_name = tk.Entry(frame_detail, width=40)
    entry_ip = tk.Entry(frame_detail, width=40)
    entry_user = tk.Entry(frame_detail, width=40)
    entry_pem = tk.Entry(frame_detail, width=40)
    entry_password = tk.Entry(frame_detail, width=40)

    for i, (label, entry) in enumerate([
        ("Tên server:", entry_name),
        ("IP:", entry_ip),
        ("Username:", entry_user),
        ("PEM key path:", entry_pem),
        ("Password:", entry_password)
    ]):
        tk.Label(frame_detail, text=label).grid(row=i, column=0, sticky="e")
        entry.grid(row=i, column=1, pady=2)

    # Buttons
    frame_buttons = tk.Frame(frame_detail)
    frame_buttons.grid(row=5, column=0, columnspan=2, pady=10)

    frame_left = tk.Frame(frame_buttons)
    frame_left.grid(row=0, column=0)

    frame_row1 = tk.Frame(frame_left)
    frame_row1.pack(pady=2)
    tk.Button(frame_row1, text="📂 import", width=12, command=import_servers_from_file).pack(side=tk.LEFT, padx=2)
    tk.Button(frame_row1, text="❓", width=4, command=show_sample_json).pack(side=tk.LEFT, padx=2)

    frame_row2 = tk.Frame(frame_left)
    frame_row2.pack(pady=2)
    tk.Button(frame_row2, text="➕ thêm", width=12, command=add_server).pack(side=tk.LEFT, padx=2)
    tk.Button(frame_row2, text="✏️ sửa", width=12, command=edit_server).pack(side=tk.LEFT, padx=2)

    tk.Button(frame_left, text="🗑️ xóa", width=28, command=delete_server).pack(pady=4)

    tk.Button(
        frame_buttons, text="🔐 kết nối", width=18, height=7,
        command=connect_ssh, bg="blue", fg="white", font=("Arial", 12, "bold")
    ).grid(row=0, column=1, padx=(20, 0))

    for entry in [entry_name, entry_ip, entry_user, entry_pem, entry_password]:
        entry.bind("<Double-Button-1>", lambda e: "break")

    load_servers()
    refresh_server_list()

# --------------------- Mẫu JSON ---------------------
def show_sample_json():
    sample_json = '''{
    "Server 1": {
        "ip": "192.200.202.1",
        "username": "root",
        "pem": "/Users/root/ssh/key.pem",
        "password": ""
    },
    "Server 2": {
        "ip": "192.168.1.100",
        "username": "admin",
        "pem": "/Users/root/keyssh",
        "password": "123456"
    }
}'''
    sample_window = tk.Toplevel()
    sample_window.title("Mẫu file servers.json")
    sample_window.geometry("500x300")

    text = tk.Text(sample_window, wrap="none")
    text.insert("1.0", sample_json)
    text.configure(state="disabled")
    text.pack(fill=tk.BOTH, expand=True)

    scroll_y = tk.Scrollbar(sample_window, orient=tk.VERTICAL, command=text.yview)
    scroll_y.pack(side=tk.RIGHT, fill=tk.Y)
    text.configure(yscrollcommand=scroll_y.set)

    scroll_x = tk.Scrollbar(sample_window, orient=tk.HORIZONTAL, command=text.xview)
    scroll_x.pack(side=tk.BOTTOM, fill=tk.X)
    text.configure(xscrollcommand=scroll_x.set)

# --------------------- Giao diện đăng nhập ---------------------
login_window = tk.Tk()
login_window.title("Login")
login_window.geometry("500x500")
login_window.protocol("WM_DELETE_WINDOW", login_window.quit)  # 👈 Đảm bảo thoát hẳn

tk.Label(login_window, text="Nhập mật khẩu:").pack(padx=10, pady=(20, 0))
password_entry = tk.Entry(login_window, show="*", width=30)
password_entry.pack(padx=10, pady=10)
password_entry.focus_set()

def check_password():
    if password_entry.get() == FIXED_PASSWORD:
        show_main_app()
    else:
        messagebox.showerror("Sai mật khẩu", "Mật khẩu không đúng!")

tk.Button(login_window, text="Login", width=15, command=check_password).pack(pady=10)
tk.Label(login_window, text="LvQuy", font=("Arial", 8), fg="gray").pack(pady=(0, 10))
password_entry.bind("<Return>", lambda event: check_password())

login_window.mainloop()
