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
    hashed_password = request.form['password']

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM Users WHERE user_id = ?", (user_id,))
    user = cursor.fetchone()

    if user:
        if user['password'] == hash_password(hashed_password):
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

    hashed_password = hash_password(password)

    cursor.execute("INSERT INTO Users (user_id, name, email, password) VALUES (?, ?, ?, ?)",
                   (user_id, name, email, hashed_password))
    conn.commit()

    cursor.execute("SELECT role_id FROM Roles WHERE role_name = ?", (role,))
    role_id = cursor.fetchone()['role_id']
    cursor.execute("INSERT INTO User_roles (user_id, role_id) VALUES (?, ?)", (user_id, role_id))
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
    
@app.route('/edit_lecturer/<class_id>', methods=['GET', 'POST'])
def edit_lecturer(class_id):
    if request.method == 'POST':
        new_lecturer_id = request.form['lecturer_id']
        
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            # Update the lecturer for the class
            cursor.execute("UPDATE Class_lecturers SET lecturer_id = ? WHERE class_id = ?", (new_lecturer_id, class_id))
            conn.commit()
            flash('Lecturer updated successfully', 'success')
        except Exception as e:
            conn.rollback()
            flash(f'Error updating lecturer: {str(e)}', 'danger')
        finally:
            conn.close()
        
        return redirect(url_for('class_list'))
    else:
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            # Retrieve all users who are lecturers
            cursor.execute("SELECT user_id, name FROM Users INNER JOIN User_roles ON Users.user_id = User_roles.user_id WHERE User_roles.role_id = 2")
            lecturers = cursor.fetchall()
        except Exception as e:
            flash(f'Error retrieving lecturers: {str(e)}', 'danger')
            lecturers = []
        finally:
            conn.close()
        
        return render_template('edit_lecturer.html', class_id=class_id, lecturers=lecturers)

    
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

@app.route('/logout')
def logout():
    session.pop("user_id" , None)
    return redirect(url_for("login"))

if __name__ == '__main__':
    app.run(debug=True)
