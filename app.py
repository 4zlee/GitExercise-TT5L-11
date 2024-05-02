from flask import Flask, render_template, request, redirect, url_for, flash
import sqlite3
import hashlib

app = Flask(__name__)
app.secret_key = 'your_secret_key'

DATABASE = 'PEER_REVIEW_DB.db'

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login_post():
    user_id = request.form['user_id']
    password = request.form['password']

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM Users WHERE user_id = ?", (user_id,))
    user = cursor.fetchone()

    if user:
        if user['password'] == password:
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Incorrect password', 'error')
            return redirect(url_for('login'))
    else:
        flash('User not found', 'error')
        return redirect(url_for('login'))

@app.route('/signup')
def signup():
    return render_template('signup.html')

@app.route('/signup', methods=['POST'])
def signup_post():
    name = request.form['name']
    user_id = request.form['user_id']
    password = request.form['password']
    role = request.form['role']

    if not name or not user_id or not password:
        flash('All fields are required', 'error')
        return redirect(url_for('signup'))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM Users WHERE user_id = ?", (user_id,))
    existing_user = cursor.fetchone()

    if existing_user:
        flash('User ID is already in use', 'error')
        return redirect(url_for('signup'))

    hashed_password = hash_password(password)

    cursor.execute("INSERT INTO Users (user_id, name, password, email) VALUES (?, ?, ?, ?)",
                   (user_id, name, hashed_password, user_id + '@example.com')) 
    conn.commit()

    cursor.execute("SELECT role_id FROM Roles WHERE role_name = ?", (role,))
    role_id = cursor.fetchone()['role_id']
    cursor.execute("INSERT INTO User_roles (user_id, role_id) VALUES (?, ?)", (user_id, role_id))
    conn.commit()

    conn.close()

    flash('Account created successfully! Please log in.', 'success')
    return redirect(url_for('login'))

@app.route('/home')
def dashboard():
    return render_template('home.html')

if __name__ == '__main__':
    app.run(debug=True)