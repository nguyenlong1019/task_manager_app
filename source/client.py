import socket
import tkinter as tk
from tkinter import Toplevel, messagebox, MULTIPLE, END
from tkinter import ttk
import json
from datetime import datetime

SERVER_IP = 'localhost'
SERVER_PORT = 5555

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((SERVER_IP, SERVER_PORT))

token = None
username = None

# Gửi yêu cầu tới server và nhận phản hồi
def send_request(request):
    client.sendall(json.dumps(request).encode())
    data = b""
    while True:
        part = client.recv(1024)
        data += part
        if len(part) < 1024:
            break
    response = json.loads(data.decode())
    return response


# Giao diện đăng ký và đăng nhập
def register():
    username = entry_username.get()
    password = entry_password.get()
    response = send_request({"action": "register", "username": username, "password": password})
    messagebox.showinfo("REGISTER", response["message"])

def login():
    global token, username
    username = entry_username.get()
    password = entry_password.get()
    response = send_request({"action": "login", "username": username, "password": password})
    if response["status"] == "success":
        token = response["token"]
        root.withdraw()  # Ẩn cửa sổ login
        main_menu()
    else:
        messagebox.showerror("LOGIN", response["message"])

def login_screen():
    global entry_username, entry_password, root
    root = tk.Tk()
    root.title("LOGIN")
    root.geometry("900x900")
    root.configure(bg="#f3e6d9")
    
    frame = ttk.Frame(root, padding="20")
    frame.pack(expand=True)

    ttk.Label(frame, text="LOGIN", font=("Arial", 28, "bold")).grid(row=0, column=0, columnspan=2, pady=20)

    ttk.Label(frame, text="USERNAME", font=("Arial", 16)).grid(row=1, column=0, sticky="w")
    entry_username = ttk.Entry(frame, width=30, font=("Arial", 16))
    entry_username.grid(row=1, column=1, pady=10)

    ttk.Label(frame, text="PASSWORD", font=("Arial", 16)).grid(row=2, column=0, sticky="w")
    entry_password = ttk.Entry(frame, show="*", width=30, font=("Arial", 16))
    entry_password.grid(row=2, column=1, pady=10)

    ttk.Button(frame, text="LOG IN", command=login).grid(row=3, column=0, columnspan=2, pady=20)
    ttk.Button(frame, text="SIGN UP", command=register).grid(row=4, column=0, columnspan=2, pady=10)

    root.mainloop()

# Giao diện chính sau khi đăng nhập
def main_menu():
    main_win = tk.Toplevel()
    main_win.title(f"HOME - {username}")
    main_win.geometry("900x900")
    main_win.configure(bg="#f3e6d9")

    frame = ttk.Frame(main_win, padding="20")
    frame.pack(expand=True)

    # Hiển thị nhãn "HOME" và thông báo chào mừng
    ttk.Label(frame, text="HOME", font=("Arial", 28, "bold")).pack(pady=20)
    ttk.Label(frame, text=f"WELCOME, {username.upper()}", font=("Arial", 18, "bold")).pack(pady=10)

    # Các nút chức năng trong Main Menu
    ttk.Button(frame, text="CHAT", command=lambda: open_chat(main_win), width=30).pack(pady=10)
    ttk.Button(frame, text="ADD PROJECT", command=lambda: add_project_screen(main_win), width=30).pack(pady=10)
    ttk.Button(frame, text="ALL PROJECTS", command=lambda: all_projects_screen(main_win), width=30).pack(pady=10)
    ttk.Button(frame, text="BACK TO LOGIN", command=lambda: back_to_login(main_win), width=30).pack(pady=10)

# Hàm quay lại giao diện đăng nhập
def back_to_login(current_window):
    current_window.destroy()
    root.deiconify()

# Giao diện chat chung
def open_chat(previous_window):
    previous_window.withdraw()
    chat_win = tk.Toplevel()
    chat_win.title(f"CHAT ROOM - {username}")
    chat_win.geometry("900x900")
    chat_win.configure(bg="#f3e6d9")

    frame = ttk.Frame(chat_win, padding="20")
    frame.pack(expand=True)

    ttk.Label(frame, text="CHAT ROOM", font=("Arial", 18, "bold")).pack(pady=10)

    chat_display = tk.Text(frame, wrap=tk.WORD, state="disabled", width=90, height=20, font=("Arial", 14))
    chat_display.pack(pady=10)

    entry_message = ttk.Entry(frame, width=70, font=("Arial", 14))
    entry_message.pack(fill=tk.X, padx=10)

    def load_chats():
        response = send_request({"action": "get_all_chats"})
        chat_display.config(state="normal")
        chat_display.delete(1.0, tk.END)
        for chat in response:
            timestamp = datetime.strptime(chat["timestamp"], '%Y-%m-%d %H:%M:%S')
            chat_display.insert(tk.END, f"{chat['username']} ({timestamp}): {chat['message']}\n")
        chat_display.config(state="disabled")

    def send_chat():
        message = entry_message.get()
        response = send_request({"action": "chat", "token": token, "message": message})
        if response["status"] == "success":
            entry_message.delete(0, tk.END)
            load_chats()
        else:
            messagebox.showerror("CHAT ROOM", response["message"])

    ttk.Button(frame, text="SEND", command=send_chat).pack(pady=10)
    ttk.Button(frame, text="LOAD", command=load_chats).pack(pady=10)
    ttk.Button(frame, text="BACK", command=lambda: back_to_main(chat_win, previous_window)).pack(pady=10)

    load_chats()

# Giao diện thêm dự án
def add_project_screen(previous_window):
    previous_window.withdraw()
    add_project_win = tk.Toplevel()
    add_project_win.title(f"ADD PROJECT - {username}")
    add_project_win.geometry("900x900")
    add_project_win.configure(bg="#f3e6d9")

    frame = ttk.Frame(add_project_win, padding="20")
    frame.pack(expand=True)

    ttk.Label(frame, text="ADD PROJECT", font=("Arial", 18, "bold")).pack(pady=20)

    ttk.Label(frame, text="PROJECT NAME", font=("Arial", 16)).pack()
    entry_project_name = ttk.Entry(frame, width=30, font=("Arial", 14))
    entry_project_name.pack(pady=10)

    ttk.Label(frame, text="SELECT MEMBERS", font=("Arial", 16)).pack()
    list_members = tk.Listbox(frame, selectmode=MULTIPLE, height=10, width=30, font=("Arial", 12))
    list_members.pack(fill=tk.BOTH, expand=True, pady=10)

    response = send_request({"action": "get_all_users"})
    if response["status"] == "success":
        for user in response["users"]:
            list_members.insert(END, user["username"])
    else:
        messagebox.showerror("ADD PROJECT", "Could not load users")

    def create_project():
        project_name = entry_project_name.get()
        members = [list_members.get(i) for i in list_members.curselection()]
        
        if not project_name:
            messagebox.showwarning("ADD PROJECT", "Project name cannot be empty.")
            return
        if not members:
            messagebox.showwarning("ADD PROJECT", "Please select at least one member.")
            return

        response = send_request({"action": "create_project", "token": token, "project_name": project_name, "members": members})
        
        if response["status"] == "error" and "already exists" in response["message"]:
            messagebox.showerror("ADD PROJECT", response["message"])
        else:
            messagebox.showinfo("ADD PROJECT", response["message"])

    ttk.Button(frame, text="CREATE PROJECT", command=create_project).pack(pady=10)
    ttk.Button(frame, text="BACK", command=lambda: back_to_main(add_project_win, previous_window)).pack(pady=10)

# Giao diện hiển thị tất cả các dự án
def all_projects_screen(previous_window):
    previous_window.withdraw()
    all_projects_win = tk.Toplevel()
    all_projects_win.title(f"ALL PROJECTS - {username}")
    all_projects_win.geometry("900x900")
    all_projects_win.configure(bg="#f3e6d9")

    frame = ttk.Frame(all_projects_win, padding="20")
    frame.pack(fill=tk.BOTH, expand=True)

    ttk.Label(frame, text="ALL PROJECTS", font=("Arial", 18, "bold")).pack(pady=20)
    style = ttk.Style()
    style.configure("TFrame", background="#f3e6d9")
    projects_frame = ttk.Frame(frame)
    projects_frame.pack()

    def load_projects():
        response = send_request({"action": "get_all_projects"})
        row = 0
        column = 0
        for project in response["projects"]:
            button = ttk.Button(projects_frame, text=project["name"], command=lambda p=project: project_details_screen(all_projects_win, p), width=30)
            button.grid(row=row, column=column, padx=10, pady=10)
            column += 1
            if column > 1:
                column = 0
                row += 1

    ttk.Button(frame, text="BACK", command=lambda: back_to_main(all_projects_win, previous_window)).pack(pady=20)
    load_projects()

# Giao diện chi tiết dự án
def project_details_screen(previous_window, project):
    previous_window.withdraw()
    project_win = tk.Toplevel()
    project_win.title(f"PROJECT DETAILS - {project['name']} - {username}")
    project_win.geometry("900x900")
    project_win.configure(bg="#f3e6d9")

    frame = ttk.Frame(project_win, padding="20")
    frame.pack(fill=tk.BOTH, expand=True)
    style = ttk.Style()
    style.configure("TFrame", background="#f3e6d9")
    ttk.Label(frame, text=f"PROJECT DETAILS - {project['name']}", font=("Arial", 18, "bold")).pack(pady=20)

    project_display = tk.Text(frame, wrap=tk.WORD, state="disabled", width=90, height=15, font=("Arial", 14))
    project_display.pack(pady=10)

    def display_project_details():
        response = send_request({"action": "get_project_members", "project_id": project["id"]})
        members = response if isinstance(response, list) else []
        tasks_response = send_request({"action": "get_project_tasks", "project_id": project["id"]})
        
        project_display.config(state="normal")
        project_display.delete(1.0, tk.END)
        project_display.insert(tk.END, f"Project Name: {project['name']}\n")
        project_display.insert(tk.END, f"Owner: {project['owner']}\n")
        project_display.insert(tk.END, f"Created At: {project['created_at']}\n")
        project_display.insert(tk.END, f"Members: {', '.join(members)}\n\n")
        project_display.insert(tk.END, "Tasks:\n")
        for task in tasks_response:
            project_display.insert(tk.END, f"Task: {task['name']} - Members: {task['members']}\n")
        project_display.config(state="disabled")

    display_project_details()

    def add_task():
        task_win = Toplevel(project_win)
        task_win.title(f"ADD TASK - {project['name']} - {username}")
        task_win.geometry("900x900")
        task_win.configure(bg="#f3e6d9")

        frame = ttk.Frame(task_win, padding="10")
        frame.pack(expand=True)

        ttk.Label(frame, text="TASK NAME", font=("Arial", 16)).pack()
        entry_task_name = ttk.Entry(frame, width=30, font=("Arial", 14))
        entry_task_name.pack(pady=10)

        ttk.Label(frame, text="ASSIGN MEMBERS", font=("Arial", 16)).pack()
        list_members = tk.Listbox(frame, selectmode=MULTIPLE, height=10, width=30, font=("Arial", 12))
        list_members.pack(fill=tk.BOTH, expand=True, pady=10)

        response = send_request({"action": "get_project_members", "project_id": project["id"]})
        for member in response:
            list_members.insert(END, member)

        def confirm_add_task():
            task_name = entry_task_name.get()
            assigned_members = [list_members.get(i) for i in list_members.curselection()]

            if not task_name:
                messagebox.showwarning("ADD TASK", "Task name cannot be empty.")
                return
            if not assigned_members:
                messagebox.showwarning("ADD TASK", "Please select at least one member.")
                return

            response = send_request({
                "action": "add_task",
                "token": token,
                "project_id": project["id"],
                "task_name": task_name,
                "assigned_members": assigned_members
            })

            if response["status"] == "error" and "already exists" in response["message"]:
                if "Updated" in response["message"]:
                    messagebox.showinfo("ADD TASK", "Task updated with new members.")
                else:
                    messagebox.showerror("ADD TASK", response["message"])
            else:
                messagebox.showinfo("ADD TASK", response["message"])
            display_project_details()

        ttk.Button(frame, text="ADD TASK", command=confirm_add_task).pack(pady=10)
        ttk.Button(frame, text="BACK", command=lambda: task_win.destroy()).pack(pady=10)

    # Chỉ hiển thị nút "Add Task" nếu người dùng là chủ dự án
    if project["owner"] == username:
        ttk.Button(frame, text="ADD TASK", command=add_task).pack(pady=10)
    ttk.Button(frame, text="BACK", command=lambda: back_to_main(project_win, previous_window)).pack(pady=10)

# Hàm quay lại giao diện chính
def back_to_main(current_window, previous_window):
    current_window.destroy()
    previous_window.deiconify()

# Chạy ứng dụng
if __name__ == "__main__":
    login_screen()
