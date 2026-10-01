from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'supersecretkey_taskflow_2026')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///tasks.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)


# --- DATABASE MODELS ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    tasks = db.relationship('Task', backref='owner', lazy=True)


class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(300))
    status = db.Column(db.String(20), default="pending")
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


# --- ROUTES ---

@app.route('/')
def home():
    if 'user_id' in session:
        user_tasks = Task.query.filter_by(user_id=session['user_id']).order_by(Task.id.desc()).all()
        return render_template('index.html', tasks=user_tasks)
    return render_template('index.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        if not username or not email or not password:
            flash('Please fill in all fields.', 'warning')
            return redirect(url_for('signup'))

        # Check if username or email already exists
        existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
        if existing_user:
            flash('Username or email is already taken. Please choose another.', 'danger')
            return redirect(url_for('signup'))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash('Account created successfully! Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()

        if user and bcrypt.check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            flash(f'Welcome back, {user.username}!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid email or password.', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


@app.route('/create-task', methods=['POST'])
def create_task():
    if 'user_id' not in session:
        flash('Please log in first.', 'warning')
        return redirect(url_for('login'))

    title = request.form.get('title')
    description = request.form.get('description')

    if not title:
        flash('Task title is required.', 'warning')
        return redirect(url_for('home'))

    new_task = Task(title=title, description=description, user_id=session['user_id'])
    db.session.add(new_task)
    db.session.commit()

    flash('Task added successfully!', 'success')
    return redirect(url_for('home'))


@app.route('/update-task/<int:task_id>', methods=['POST'])
def update_task(task_id):
    if 'user_id' not in session:
        flash('Please log in first.', 'warning')
        return redirect(url_for('login'))

    task = Task.query.filter_by(id=task_id, user_id=session['user_id']).first()
    if not task:
        flash('Task not found.', 'danger')
        return redirect(url_for('home'))

    new_status = request.form.get('status')
    if new_status:
        task.status = new_status

    db.session.commit()
    flash('Task status updated!', 'info')
    return redirect(url_for('home'))


@app.route('/delete-task/<int:task_id>', methods=['POST'])
def delete_task(task_id):
    if 'user_id' not in session:
        flash('Please log in first.', 'warning')
        return redirect(url_for('login'))

    task = Task.query.filter_by(id=task_id, user_id=session['user_id']).first()
    if not task:
        flash('Task not found.', 'danger')
        return redirect(url_for('home'))

    db.session.delete(task)
    db.session.commit()
    flash('Task deleted.', 'secondary')
    return redirect(url_for('home'))


# --- OPTIONAL API ENDPOINT ---
@app.route('/api/tasks', methods=['GET'])
def api_tasks():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    tasks = Task.query.filter_by(user_id=session['user_id']).all()
    task_list = []
    for task in tasks:
        task_list.append({
            'id': task.id,
            'title': task.title,
            'description': task.description,
            'status': task.status
        })
    return jsonify(task_list)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)