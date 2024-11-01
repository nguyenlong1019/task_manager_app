import socket
import threading
import logging
import os
import datetime
import sqlite3
import json
from hashlib import sha256
import jwt
import tkinter as tk
from tkinter import scrolledtext

# Khởi tạo cơ sở dữ liệu và tạo bảng nếu chưa tồn tại
def initialize_database():
    conn = sqlite3.connect('db.sqlite3')
    cur = conn.cursor()
    cur.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE,
                        password TEXT,
                        role TEXT,
                        token TEXT
                    )''')
    cur.execute('''CREATE TABLE IF NOT EXISTS projects (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT,
                        owner INTEGER,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY(owner) REFERENCES users(id)
                    )''')
    cur.execute('''CREATE TABLE IF NOT EXISTS project_members (
                        project_id INTEGER,
                        user_id INTEGER,
                        FOREIGN KEY(project_id) REFERENCES projects(id),
                        FOREIGN KEY(user_id) REFERENCES users(id)
                    )''')
    cur.execute('''CREATE TABLE IF NOT EXISTS chats (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER,
                        message TEXT,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY(user_id) REFERENCES users(id)
                    )''')
    cur.execute('''CREATE TABLE IF NOT EXISTS tasks (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        project_id INTEGER,
                        name TEXT,
                        FOREIGN KEY(project_id) REFERENCES projects(id)
                    )''')
    cur.execute('''CREATE TABLE IF NOT EXISTS task_assignments (
                        task_id INTEGER,
                        user_id INTEGER,
                        FOREIGN KEY(task_id) REFERENCES tasks(id),
                        FOREIGN KEY(user_id) REFERENCES users(id)
                    )''')
    conn.commit()
    conn.close()

# Thiết lập logging theo ngày và phân loại
def setup_logging(action):
    today = datetime.datetime.now().strftime("%d_%m_%Y")
    log_dir = f'logs/{today}'
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, f'{action}.log')
    handler = logging.FileHandler(log_file, encoding="utf-8")
    handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
    logger = logging.getLogger(action)
    logger.setLevel(logging.INFO)
    logger.addHandler(handler)
    return logger

register_logger = setup_logging('register')
login_logger = setup_logging('login')
chat_logger = setup_logging('chat')
project_logger = setup_logging('project')

SECRET_KEY = 'your_secret_key'
conn = sqlite3.connect('db.sqlite3', check_same_thread=False)
cur = conn.cursor()

# Các hàm xử lý đăng ký, đăng nhập, chat, tạo project và thêm thành viên
def register(username, password):
    hashed_password = sha256(password.encode()).hexdigest()
    try:
        cur.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", (username, hashed_password, 'user'))
        conn.commit()
        register_logger.info(f"User registered: {username}")
        return {"status": "success", "message": "User registered successfully"}
    except sqlite3.IntegrityError:
        register_logger.warning(f"Failed registration attempt: Username {username} already exists.")
        return {"status": "error", "message": "Username already exists"}

def login(username, password):
    hashed_password = sha256(password.encode()).hexdigest()
    cur.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, hashed_password))
    user = cur.fetchone()
    if user:
        token = jwt.encode({"username": username}, SECRET_KEY, algorithm="HS256")
        cur.execute("UPDATE users SET token = ? WHERE id = ?", (token, user[0]))
        conn.commit()
        login_logger.info(f"User logged in: {username}")
        return {"status": "success", "token": token}
    else:
        login_logger.warning(f"Failed login attempt: Invalid credentials for {username}.")
        return {"status": "error", "message": "Invalid username or password"}

def create_project(token, project_name, members):
    decoded_token = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    username = decoded_token['username']
    cur.execute("SELECT id FROM users WHERE username = ?", (username,))
    user = cur.fetchone()
    if user:
        cur.execute("INSERT INTO projects (name, owner) VALUES (?, ?)", (project_name, user[0]))
        project_id = cur.lastrowid
        conn.commit()
        
        # Thêm thành viên vào project
        for member in members:
            cur.execute("SELECT id FROM users WHERE username = ?", (member,))
            user_to_add = cur.fetchone()
            if user_to_add:
                cur.execute("INSERT INTO project_members (project_id, user_id) VALUES (?, ?)", (project_id, user_to_add[0]))
        conn.commit()
        
        project_logger.info(f"Project created: {project_name} by {username} with members {members}")
        return {"status": "success", "message": "Project created successfully"}
    return {"status": "error", "message": "Authentication failed"}

def get_all_projects():
    cur.execute("SELECT p.id, p.name, u.username, p.created_at FROM projects p JOIN users u ON p.owner = u.id")
    projects = cur.fetchall()
    result = [{"id": proj[0], "name": proj[1], "owner": proj[2], "created_at": proj[3]} for proj in projects]
    return {"status": "success", "projects": result}

def get_project_members(project_id):
    cur.execute("SELECT u.username FROM project_members pm JOIN users u ON pm.user_id = u.id WHERE pm.project_id = ?", (project_id,))
    members = cur.fetchall()
    return [member[0] for member in members]

def add_task(token, project_id, task_name, assigned_members):
    decoded_token = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    username = decoded_token['username']
    
    # Xác minh người dùng là chủ sở hữu của project
    cur.execute("SELECT owner FROM projects WHERE id = ?", (project_id,))
    project = cur.fetchone()
    if project and project[0] == cur.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()[0]:
        cur.execute("INSERT INTO tasks (project_id, name) VALUES (?, ?)", (project_id, task_name))
        task_id = cur.lastrowid
        conn.commit()
        
        # Thêm người thực hiện vào task
        for member in assigned_members:
            cur.execute("SELECT id FROM users WHERE username = ?", (member,))
            user_to_assign = cur.fetchone()
            if user_to_assign:
                cur.execute("INSERT INTO task_assignments (task_id, user_id) VALUES (?, ?)", (task_id, user_to_assign[0]))
        conn.commit()
        
        project_logger.info(f"Task '{task_name}' created in project {project_id} with members {assigned_members}")
        return {"status": "success", "message": "Task created successfully"}
    return {"status": "error", "message": "Only the project owner can add tasks"}

def get_project_tasks(project_id):
    cur.execute("SELECT t.id, t.name, GROUP_CONCAT(u.username, ', ') as members FROM tasks t LEFT JOIN task_assignments ta ON t.id = ta.task_id LEFT JOIN users u ON ta.user_id = u.id WHERE t.project_id = ? GROUP BY t.id", (project_id,))
    tasks = cur.fetchall()
    return [{"id": task[0], "name": task[1], "members": task[2] or ""} for task in tasks]

def chat(token, message):
    decoded_token = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    username = decoded_token['username']
    cur.execute("SELECT id FROM users WHERE username = ?", (username,))
    user = cur.fetchone()
    if user:
        cur.execute("INSERT INTO chats (user_id, message) VALUES (?, ?)", (user[0], message))
        conn.commit()
        chat_logger.info(f"Message from {username}: {message}")
        return {"status": "success", "message": "Message sent"}
    return {"status": "error", "message": "Authentication failed"}

def get_all_chats():
    cur.execute("SELECT u.username, c.message, c.timestamp FROM chats c JOIN users u ON c.user_id = u.id ORDER BY c.timestamp")
    chats = cur.fetchall()
    return [{"username": chat[0], "message": chat[1], "timestamp": chat[2]} for chat in chats]

def get_all_users():
    cur.execute("SELECT username FROM users")
    users = cur.fetchall()
    result = [{"username": user[0]} for user in users]
    return {"status": "success", "users": result}

def handle_client(conn, addr, log_display):
    with conn:
        while True:
            try:
                data = conn.recv(1024).decode()
                if not data:
                    break
                request = json.loads(data)
                action = request.get("action")
                if action == "register":
                    response = register(request["username"], request["password"])
                elif action == "login":
                    response = login(request["username"], request["password"])
                elif action == "get_all_users":
                    response = get_all_users()
                elif action == "create_project":
                    response = create_project(request["token"], request["project_name"], request["members"])
                elif action == "get_all_projects":
                    response = get_all_projects()
                elif action == "get_project_members":
                    response = get_project_members(request["project_id"])
                elif action == "add_task":
                    response = add_task(request["token"], request["project_id"], request["task_name"], request["assigned_members"])
                elif action == "get_project_tasks":
                    response = get_project_tasks(request["project_id"])
                elif action == "chat":
                    response = chat(request["token"], request["message"])
                elif action == "get_all_chats":
                    response = get_all_chats()
                else:
                    response = {"status": "error", "message": "Invalid action"}
                conn.sendall(json.dumps(response).encode())
                log_display.insert(tk.END, f"[{addr}] {action}: {response}\n")
                log_display.yview(tk.END)
            except Exception as e:
                logging.error(f"Error: {e}")

def start_server_ui():
    initialize_database()
    
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('localhost', 5555))
    server.listen(100)

    def server_accept():
        while True:
            conn, addr = server.accept()
            threading.Thread(target=handle_client, args=(conn, addr, log_display)).start()
            log_display.insert(tk.END, f"Connected by {addr}\n")
            log_display.yview(tk.END)

    root = tk.Tk()
    root.title("Server Log")
    root.geometry("500x400")
    log_display = scrolledtext.ScrolledText(root, wrap=tk.WORD, state="normal")
    log_display.pack(fill=tk.BOTH, expand=True)

    threading.Thread(target=server_accept).start()
    root.mainloop()

if __name__ == "__main__":
    start_server_ui()
