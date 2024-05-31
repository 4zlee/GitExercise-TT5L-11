from flask import Flask, render_template, request, session, jsonify, redirect, url_for, flash
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

def get_lecturer_email(lecturer_id):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("SELECT email FROM Users WHERE user_id = ?", (lecturer_id,))
    lecturer_email = cursor.fetchone()[0]
    conn.close()
    return lecturer_email

# This function can be used to fetch lecturer's app password from the database
def get_lecturer_app_password(lecturer_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT app_password FROM lecturer_app_passwords WHERE lecturer_id = ?", (lecturer_id,))
    app_password = cursor.fetchone()[0]
    conn.close()
    return app_password

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
        app_password = get_lecturer_app_password(lecturer_id)

        # Configure Flask-Mail with the lecturer's email and app password
        app.config['MAIL_USERNAME'] = lecturer_email
        app.config['MAIL_PASSWORD'] = app_password

        mail = Mail(app)  # Reinitialize mail with the new configuration

        student_email = request.form['student_email']
        class_id = request.form['class_id']
        group_id = request.form['group_id']

        # Check if the student exists
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT user_id FROM Users WHERE email = ?", (student_email,))
        student = cursor.fetchone()

        if student:
            student_id = student['user_id']

        else:
            student_id = cursor.lastrowid

            # Assign the student role
            cursor.execute("SELECT role_id FROM Roles WHERE role_name = 'student'")
            role_id = cursor.fetchone()['role_id']
            cursor.execute("INSERT INTO User_roles (user_id, role_id) VALUES (?, ?)", (student_id, role_id))
            conn.commit()

        # Check if the student is already in the group
        cursor.execute("SELECT * FROM group_members WHERE user_id = ? AND group_id = ?", (student_id, group_id))
        existing_membership = cursor.fetchone()

        if existing_membership is None:
            # If the student is not already in the group, insert the new membership
            cursor.execute("INSERT INTO group_members (user_id, group_id, class_id) VALUES (?, ?, ?)",
                        (student_id, group_id, class_id))
            conn.commit()
        else:
            # If the student is already in the group, you may choose to log this or handle it differently
            print("Student is already a member of the group")

        # Generate the URL for the signup_invited route with class_id and group_id parameters
        signup_url = url_for('signup_invited', class_id=class_id, group_id=group_id, _external=True)

        # Send email to the student with a link to the signup page
        msg = Message('Invitation to Join Class and Group', sender=lecturer_email, recipients=[student_email])
        msg.body = f'You have been invited to join the class. Please sign up using the following link: {signup_url}'
        try:
            mail.send(msg)
            flash('Email sent successfully!', 'success')
        except Exception as e:
            flash(f'Error sending email: {str(e)}', 'error')

        # Redirect back to the add_students page
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

@app.route('/signup_invited', methods=['GET', 'POST'])
def signup_invited():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        class_id = request.form['class_id']
        group_id = request.form['group_id']

        conn = get_db_connection()
        cursor = conn.cursor()

        # Check if the email is already in use
        cursor.execute("SELECT * FROM Users WHERE email = ?", (email,))
        existing_user = cursor.fetchone()

        if existing_user:
            existing_user_id = existing_user['user_id']
            cursor.execute("SELECT group_id FROM group_members WHERE user_id = ? AND class_id = ?", (existing_user_id, class_id))
            existing_group = cursor.fetchone()

            if existing_group:
                flash('User is already a member of a group in the provided class', 'warning')
                conn.close()
                return redirect(url_for('login'))

            else:
                cursor.execute("INSERT INTO group_members (user_id, group_id, class_id) VALUES (?, ?, ?)",
                            (existing_user_id, group_id, class_id))
                flash('Welcome back! Added to the group successfully', 'success')

            conn.commit()
            conn.close()

            return redirect(url_for('login'))
        else:
            try:
                # If the user is not existing, create a new user record
                hashed_password = hash_password(password)
                cursor.execute("INSERT INTO Users (name, email, password) VALUES (?, ?, ?)",
                               (name, email, hashed_password))
                user_id = cursor.lastrowid

                # Assign the student role to the new user
                cursor.execute("SELECT role_id FROM Roles WHERE role_name = 'student'")
                role_id = cursor.fetchone()['role_id']
                cursor.execute("INSERT INTO User_roles (user_id, role_id) VALUES (?, ?)", (user_id, role_id))

                # Add the new user to the specified group
                cursor.execute("INSERT INTO group_members (user_id, group_id, class_id) VALUES (?, ?, ?)",
                               (user_id, group_id, class_id))

                conn.commit()
                flash('Signup successful!', 'success')
            except Exception as e:
                conn.rollback()
                flash(f'Error signing up: {str(e)}', 'danger')
            finally:
                conn.close()

            return redirect(url_for('login'))
    else:
        class_id = request.args.get('class_id')
        group_id = request.args.get('group_id')
        return render_template('signup_invited.html', class_id=class_id, group_id=group_id)

@app.route('/signup')
def signup():
    return render_template('signup.html')

@app.route('/signup', methods=['POST'])
def signup_post():
    name = request.form['name']
    password = request.form['password']
    app_password = request.form['app_password']
    email = request.form['email']
    role = request.form['role']
    class_id = request.form.get('class_id')
    group_id = request.form.get('group_id')

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

    cursor.execute("INSERT INTO lecturer_app_passwords (lecturer_id, app_password) VALUES (?, ?)", (new_user_id, app_password))
    conn.commit()

    if class_id and group_id:
        cursor.execute("INSERT INTO group_members (group_id, class_id, user_id) VALUES (?, ?, ?)", (group_id, class_id, new_user_id))
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

@app.route('/students_list')
def students_list():
    lecturer_id = session.get('user_id')
    
    if lecturer_id:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT Users.user_id, Users.name, Users.email, Classes.class_name
            FROM Users
            INNER JOIN group_members ON Users.user_id = group_members.user_id
            INNER JOIN Classes ON group_members.class_id = Classes.class_id
            WHERE Classes.class_id IN (
                SELECT class_id FROM Class_lecturers WHERE lecturer_id = ?
            )
            AND Users.user_id IN (
                SELECT user_id FROM User_roles WHERE role_id = (
                    SELECT role_id FROM Roles WHERE role_name = 'student'
                )
            )
            GROUP BY Users.user_id, Users.name, Users.email
        """, (lecturer_id,))
        students = cursor.fetchall()
        conn.close()
        
        return render_template('students_list.html', students=students)
    else:
        return redirect(url_for('login'))

@app.route('/edit_students', methods=['POST', 'GET'])
def edit_students():
    if request.method == 'POST':
        user_id = request.form.get('user_id')

        if user_id:
            name = request.form['name']
            email = request.form['email']

            conn = get_db_connection()
            cursor = conn.cursor()
            
            try:
                cursor.execute("UPDATE Users SET name = ?, email = ? WHERE user_id = ?", (name, email, user_id))
                
                conn.commit()
                flash('Student details updated successfully', 'success')
            except Exception as e:
                conn.rollback()
                flash(f'Error updating student details: {str(e)}', 'danger')
            finally:
                conn.close()

            return redirect(url_for('students_list'))
        else:
            flash('User ID not provided', 'danger')
            return redirect(url_for('students_list'))
    else:
        user_id = request.args.get('user_id')

        if user_id:
            conn = get_db_connection()
            cursor = conn.cursor()
            try:
                cursor.execute("SELECT Users.name, Users.email FROM Users WHERE Users.user_id = ?", (user_id,))
                student = cursor.fetchone()

            except Exception as e:
                flash(f'Error retrieving student details: {str(e)}', 'danger')
                student = None
            finally:
                conn.close()

            return render_template('edit_students.html', student=student, user_id=user_id)
        else:
            flash('User ID not provided', 'danger')
            return redirect(url_for('students_list'))
        
@app.route('/delete_student/<int:user_id>')
def delete_student(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # Delete student from the database
        cursor.execute("DELETE FROM group_members WHERE user_id = ?", (user_id,))
        conn.commit()
        flash('Student successfully removed', 'success')
    except Exception as e:
        conn.rollback()
        flash(f'Error deleting student: {str(e)}', 'danger')
    finally:
        conn.close()
    return redirect(url_for('students_list'))

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
    
@app.route('/get_groups/<class_id>')
def get_groups(class_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT group_id, group_name FROM Groups WHERE class_id = ?", (class_id,))
    groups = cursor.fetchall()
    conn.close()
    return jsonify({'groups': [{'group_id': group['group_id'], 'group_name': group['group_name']} for group in groups]})

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

@app.route('/group_list')
def group_list():
    lecturer_id = session.get('user_id')
    
    if lecturer_id:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT Users.user_id, Users.name, Classes.class_name, Groups.group_name 
            FROM Users
            INNER JOIN group_members ON Users.user_id = group_members.user_id
            INNER JOIN Classes ON group_members.class_id = Classes.class_id
            INNER JOIN Groups ON group_members.group_id = Groups.group_id
            WHERE group_members.class_id IN (
                SELECT class_id FROM Class_lecturers WHERE lecturer_id = ?
            )
            AND Users.user_id IN (
                SELECT user_id FROM User_roles WHERE role_id = (
                    SELECT role_id FROM Roles WHERE role_name = 'student'
                )
            )
        """, (lecturer_id,))
        group_members_stu = cursor.fetchall()
        conn.close()
        
        # Debugging
        print("Fetched students data:", group_members_stu)
        
        return render_template('group_list.html', group_members_stu=group_members_stu)
    else:
        return "No user logged in"
    
@app.route('/add_group')
def add_group():
    if "user_id" in session:
        user_id = session["user_id"]

        # Fetch classes from the database
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT class_id, class_name FROM Classes")
        classes = cursor.fetchall()

        # Fetch groups from the database (you may need to filter by the selected class)
        cursor.execute("SELECT group_id, group_name FROM Groups")
        groups = cursor.fetchall()

        conn.close()

        return render_template('add_group.html' , classes=classes, groups=groups)
    else:
        return redirect(url_for('login'))
    
@app.route('/edit_group/<group_id>', methods=['GET', 'POST'])
def edit_group(group_id):
    if request.method == 'POST':
        new_group_name = request.form['group_name']
        lecturer_id = session.get("user_id")
        
        if lecturer_id:
            conn = get_db_connection()
            cursor = conn.cursor()
            try:
                # Update group name in the database
                cursor.execute("UPDATE Groups SET group_name = ? WHERE group_id = ?", (new_group_name, group_id))
                conn.commit()
                flash('Group updated successfully', 'success')
            except Exception as e:
                conn.rollback()
                flash(f'Error updating group: {str(e)}', 'danger')
            finally:
                conn.close()
            
            return redirect(url_for('group_list'))
        else:
            flash("No user logged in", "danger")
            return redirect(url_for('group_list'))
    else:
        lecturer_id = session.get("user_id")
        
        if lecturer_id:
            conn = get_db_connection()
            cursor = conn.cursor()
            try:
                # Retrieve group details from the database
                cursor.execute("""
                    SELECT Users.user_id, Users.name, Classes.class_name, Groups.group_name 
                    FROM Users
                    INNER JOIN group_members ON Users.user_id = group_members.user_id
                    INNER JOIN Classes ON group_members.class_id = Classes.class_id
                    INNER JOIN Groups ON group_members.group_id = Groups.group_id
                    WHERE group_members.class_id IN (
                        SELECT class_id FROM Class_lecturers WHERE lecturer_id = ?
                    )
                    AND Users.user_id IN (
                        SELECT user_id FROM User_roles WHERE role_id = (
                            SELECT role_id FROM Roles WHERE role_name = 'student'
                        )
                    )
                    AND Groups.group_id = ?
                """, (lecturer_id, group_id))
                group_details = cursor.fetchone()
                group_name = group_details['group_name'] if group_details else None
            except Exception as e:
                flash(f'Error retrieving group details: {str(e)}', 'danger')
                group_name = None
            finally:
                conn.close()
            
            return render_template('edit_group.html', group_id=group_id, group_name=group_name)
        else:
            flash("No user logged in", "danger")
            return redirect(url_for('group_list'))
    

@app.route('/delete_group/<int:user_id>')
def delete_group(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # Delete student from the database
        cursor.execute("DELETE FROM group_members WHERE user_id = ?", (user_id,))
        conn.commit()
        flash('Student successfully removed', 'success')
    except Exception as e:
        conn.rollback()
        flash(f'Error deleting student: {str(e)}', 'danger')
    finally:
        conn.close()
    return redirect(url_for('group_list'))
@app.route('/logout')
def logout():
    session.pop("user_id" , None)
    return redirect(url_for("login"))

if __name__ == '__main__':
    app.run(debug=True)