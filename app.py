from flask import Flask, render_template, request, session, redirect, url_for, flash
import sqlite3
import hashlib
import re
from flask_mail import Mail, Message
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Flask-Mail configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = 'alexxaviera081@gmail.com'  # Lecturer's email address
app.config['MAIL_PASSWORD'] = 'yttmlbbokdiqrnby'     # App password for lecturer's email

def get_lecturer_email(lecturer_id):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("SELECT email FROM Users WHERE user_id = ?", (lecturer_id,))
    lecturer_email = cursor.fetchone()[0]
    conn.close()
    return lecturer_email

mail = Mail(app)

email_pattern = r'^[\w\.-]+@[a-zA-Z0-9-]+\.[a-zA-Z]{2,}$'

DATABASE = 'PEER_REVIEW_DB.db'

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

@app.route('/send_email', methods=['POST'])
def send_email():
    if request.method == 'POST':
        lecturer_id = session.get('user_id')
        lecturer_email = get_lecturer_email(lecturer_id)
        student_email = request.form['student_email']

        # Send email to the student
        try:
            msg = Message('Hello from Flask', sender=lecturer_email, recipients=[student_email])
            msg.body = 'Hi there! This is a test email sent from Flask.'
            mail.send(msg)
            flash('Email sent successfully!', 'success')
        except Exception as e:
            flash(f'Error sending email: {str(e)}', 'error')

        return redirect(url_for('add_students'))

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
    email = request.form['email']
    hashed_password = request.form['password']

    if not re.match(email_pattern, email):
        flash('Invalid email address', 'danger')
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM Users WHERE email = ?", (email,))
    user = cursor.fetchone()

    if user:
        if user['password'] == hash_password(hashed_password):
            session["user_id"] = user['user_id']
            role_id = get_user_role_id(user['user_id'])
            if role_id == 1:
                return redirect(url_for('home_stu'))
            else:
                return redirect(url_for('home_lec'))
        else:
            flash('Incorrect password', 'danger')
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
    password = request.form['password']
    email = request.form['email']
    role = request.form['role']

    if not name or not password:
        flash('All fields are required', 'error')
        return redirect(url_for('signup'))

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM Users WHERE email = ?", (email,))
    existing_user = cursor.fetchone()

    if existing_user:
        flash('Email is already in use', 'danger')
        return redirect(url_for('signup'))

    hashed_password = hash_password(password)

    cursor.execute("INSERT INTO Users (name, email, password) VALUES (?, ?, ?)",
                   (name, email, hashed_password))
    conn.commit()

    new_user_id = cursor.lastrowid

    cursor.execute("SELECT role_id FROM Roles WHERE role_name = ?", (role,))
    role_id = cursor.fetchone()['role_id']
    cursor.execute("INSERT INTO User_roles (user_id, role_id) VALUES (?, ?)", (new_user_id, role_id))
    conn.commit()

    conn.close()

    flash('Account created successfully! Please log in.', 'success')
    return redirect(url_for('login'))

@app.route('/class_add', methods=['POST', 'GET'])
def class_add_post():
    if request.method == 'POST':
        class_id = request.form['class_id']
        class_name = request.form['class_name']
        lecturer_id = session['user_id']  # Get the current lecturer's ID from the session

        # Check if class already exists
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM Classes WHERE class_id = ?", (class_id,))
        existing_class = cursor.fetchone()

        if existing_class:
            flash('Class ID is already in use', 'danger')
            return redirect(url_for('class_add_post'))

        # Insert new class into the database
        cursor.execute("INSERT INTO Classes (class_id, class_name) VALUES (?, ?)",
                       (class_id, class_name))
        conn.commit()

        # Assign lecturer to the class
        cursor.execute("INSERT INTO Class_lecturers (class_id, lecturer_id) VALUES (?, ?)", (class_id, lecturer_id))
        conn.commit()

        conn.close()

        flash('Class created successfully', 'success')
        return redirect(url_for('class_add_post'))

    # If GET request, render the class add form
    return render_template('class_add.html')

@app.route('/class_list')
def class_list():
    lecturer_id = session.get('user_id')
    
    if lecturer_id:
        conn = get_db_connection()
        cursor = conn.cursor()
       
        cursor.execute("SELECT Classes.class_id, Classes.class_name, Users.name AS lecturer_name FROM Classes INNER JOIN Class_lecturers ON Classes.class_id = Class_lecturers.class_id INNER JOIN Users ON Class_lecturers.lecturer_id = Users.user_id WHERE Users.user_id = ?", (lecturer_id,))
        classes = cursor.fetchall()
        conn.close()
        return render_template('class_list.html', classes=classes)
    else:
        return "No user logged in"

@app.route('/edit_class/<class_id>', methods=['GET', 'POST'])
def edit_class(class_id):
    if request.method == 'POST':
        new_class_name = request.form['class_name']
        
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            # Update class name in the database
            cursor.execute("UPDATE Classes SET class_name = ? WHERE class_id = ?", (new_class_name, class_id))
            conn.commit()
            flash('Class updated successfully', 'success')
        except Exception as e:
            conn.rollback()
            flash(f'Error updating class: {str(e)}', 'danger')
        finally:
            conn.close()
        
        return redirect(url_for('class_list'))
    else:
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            # Retrieve class details from the database
            cursor.execute("SELECT class_name FROM Classes WHERE class_id = ?", (class_id,))
            class_details = cursor.fetchone()
            class_name = class_details['class_name']
        except Exception as e:
            flash(f'Error retrieving class details: {str(e)}', 'danger')
            class_name = None
        finally:
            conn.close()
        
        return render_template('edit_class.html', class_id=class_id, class_name=class_name)
    
@app.route('/delete_class/<class_id>')
def delete_class(class_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # Delete class from the database
        cursor.execute("DELETE FROM Classes WHERE class_id = ?", (class_id,))
        conn.commit()
        flash('Class successfully deleted', 'success')
    except Exception as e:
        conn.rollback()
        flash(f'Error deleting class: {str(e)}', 'danger')
    finally:
        conn.close()
    return redirect(url_for('class_list'))

@app.route('/add_students')
def add_students():
    if "user_id" in session:
        user_id = session["user_id"]
        lecturer_email = get_lecturer_email(user_id)

        # Fetch classes from the database
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT class_id, class_name FROM Classes")
        classes = cursor.fetchall()

        # Fetch groups from the database (you may need to filter by the selected class)
        cursor.execute("SELECT group_id, group_name FROM Groups")
        groups = cursor.fetchall()

        conn.close()

        return render_template('add_students.html', lecturer_email= lecturer_email , classes=classes, groups=groups)
    else:
        return redirect(url_for('login'))

@app.route('/students_list')
def students_list():
   pass

@app.route('/join_class/<class_id>')
def join_class(class_id):
    # Logic to join the class...
    flash(f'Joined class with ID: {class_id}', 'success')
    return redirect(url_for('home_stu'))

# Route to join a group
@app.route('/join_group/<group_id>')
def join_group(group_id):
    # Logic to join the group...
    flash(f'Joined group with ID: {group_id}', 'success')
    return redirect(url_for('home_stu'))

@app.route('/add_group', methods=['GET', 'POST'])
def add_group():
    if request.method == 'POST':
        class_id = request.form['class_id']
        group_name = request.form['group_name']
        students = request.form.getlist('students[]')

        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            # Insert new group into the database
            cursor.execute("INSERT INTO Groups (class_id, group_name) VALUES (?, ?)", (class_id, group_name))
            group_id = cursor.lastrowid

            # Insert group members into the database
            for student_id in students:
                cursor.execute("INSERT INTO group_members (user_id, group_id) VALUES (?, ?)", (student_id, group_id))

            conn.commit()
            flash('Group added successfully', 'success')
        except Exception as e:
            conn.rollback()
            flash(f'Error adding group: {str(e)}', 'danger')
        finally:
            conn.close()

        return redirect(url_for('add_group'))

    # If GET request, render the add group form
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT Users.user_id, Users.name FROM Users INNER JOIN User_roles ON Users.user_id = User_roles.user_id WHERE User_roles.role_id = 1")
    students = cursor.fetchall()
    cursor.execute("SELECT class_id, class_name FROM Classes")
    classes = cursor.fetchall()
    conn.close()
    return render_template('add_group.html', classes=classes, students=students)

@app.route('/logout')
def logout():
    session.pop("user_id" , None)
    return redirect(url_for("login"))

if __name__ == '__main__':
    app.run(debug=True)
