from flask import Flask, render_template, request, session, redirect, url_for, flash
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

@app.route('/home_stu')
def home_stu():
    if "user_id" in session:
        user_id = session["user_id"]
        user_name = get_user_name(user_id)
        return render_template('home_stu.html', user_name=user_name)
    else:
        return redirect(url_for('login'))

@app.route('/home_lec')
def home_lec():
    if "user_id" in session:
        user_id = session["user_id"]
        user_name = get_user_name(user_id)
        return render_template('home_lec.html', user_name=user_name)
    else:
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
            session["user_id"] = user_id
            role_id = get_user_role_id(user_id)
            if role_id == 1:
                return redirect(url_for('home_stu'))
            else:
                return redirect(url_for('home_lec'))
        else:
            flash('Incorrect password', 'danger')
            return redirect(url_for('login'))
    else:
        flash('User not found', 'danger')
        return redirect(url_for('login'))

def get_user_role_id(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT role_id FROM User_roles WHERE user_id = ?", (user_id,))
    role_id = cursor.fetchone()['role_id']
    conn.close()
    return role_id

def get_user_name(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM Users WHERE user_id = ?", (user_id,))
    user_name = cursor.fetchone()['name']
    conn.close()
    return user_name

@app.route('/signup')
def signup():
    return render_template('signup.html')

@app.route('/signup', methods=['POST'])
def signup_post():
    name = request.form['name']
    user_id = request.form['user_id']
    password = request.form['password']
    email = request.form['email']
    role = request.form['role']

    if not name or not user_id or not password:
        flash('All fields are required', 'error')
        return redirect(url_for('signup'))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM Users WHERE user_id = ?", (user_id,))
    existing_user = cursor.fetchone()

    if existing_user:
        flash('User ID is already in use', 'danger')
        return redirect(url_for('signup'))

    #hashed_password = hash_password(password)

    cursor.execute("INSERT INTO Users (user_id, name, email, password) VALUES (?, ?, ?, ?)",
                   (user_id, name, email, password))
                   #(user_id, name, user_id + '@example.com', password)) 
    conn.commit()

    cursor.execute("SELECT role_id FROM Roles WHERE role_name = ?", (role,))
    role_id = cursor.fetchone()['role_id']
    cursor.execute("INSERT INTO User_roles (user_id, role_id) VALUES (?, ?)", (user_id, role_id))
    conn.commit()

    conn.close()

    flash('Account created successfully! Please log in.', 'success')
    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.pop("user_id" , None)
    return redirect(url_for("login"))

if __name__ == '__main__':
    app.run(debug=True)
