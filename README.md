# 📝 TaskFlow - Task Management System

A full-stack web application built with **Flask**, **SQLite**, **SQLAlchemy**, and **Bootstrap 5**.

---

## ✨ Features

- **User Authentication**: Secure Sign Up and Login with password hashing using `Bcrypt`.
- **Session Management**: Persistent user sessions so users stay logged in.
- **Task Management (CRUD)**:
  - **Create**: Add new tasks with title and optional description.
  - **Read**: View tasks in a clean dashboard with statistics (Total, Pending, Completed).
  - **Update**: Toggle tasks between Pending and Completed.
  - **Delete**: Remove completed or unwanted tasks.
- **Responsive UI**: Modern interface built with Bootstrap 5 and Bootstrap Icons.
- **RESTful API**: Optional `/api/tasks` endpoint for programmatic access.

---

## 🚀 Getting Started

### 1. Clone the repository
```bash
git clone https://github.com/vybhavigujjar/task-management-system.git
cd task-management-system
```

### 2. Set up virtual environment
```bash
python -m venv venv
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Run the app
```bash
python app.py
```
Open your browser and navigate to `http://127.0.0.1:5000`.

---

## 🌐 Deployment

This application is ready to deploy on **Render**, **Railway**, or **PythonAnywhere**:
- **Build Command**: `pip install -r requirements.txt`
- **Start Command**: `gunicorn app:app`