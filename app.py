from flask import Flask, render_template, request, session, jsonify, redirect, url_for, flash
import sqlite3
import hashlib
import re
import pandas as pd
from flask_mail import Mail, Message
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Flask-Mail configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True

def normalize_rating(rating, old_min=0, old_max=5, new_min=0, new_max=3):
    """
    Normalize a rating from the old range (old_min, old_max) to the new range (new_min, new_max).
    
    Parameters:
    rating (float): The rating to be normalized.
    old_min (float): The minimum value of the old range. Default is 0.
    old_max (float): The maximum value of the old range. Default is 5.
    new_min (float): The minimum value of the new range. Default is 0.
    new_max (float): The maximum value of the new range. Default is 3.
    
    Returns:
    float: The normalized rating in the new range.
    """
    # Ensure the rating is within the old range
    if rating < old_min or rating > old_max:
        raise ValueError(f"Rating {rating} is out of bounds. It should be between {old_min} and {old_max}.")
    
    # Normalize the rating
    normalized_rating = ((rating - old_min) / (old_max - old_min)) * (new_max - new_min) + new_min
    return normalized_rating

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

        if not re.match(email_pattern, student_email):
            flash('Invalid email address', 'danger')

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





@app.route('/select_class', methods=['GET', 'POST'])
def select_class():
    if "user_id" not in session:
        return redirect(url_for('login'))

    user_id = session["user_id"]
    conn = get_db_connection()
    cursor = conn.cursor()

    # Get the list of classes the student is enrolled in
    cursor.execute("""
        SELECT c.class_id, c.class_name
        FROM Student_class sc
        JOIN Classes c ON sc.class_id = c.class_id
        WHERE sc.student_id = ?
    """, (user_id,))
    classes = cursor.fetchall()

    if request.method == 'POST':
        class_id = request.form['class_id']

        # Fetch the group information for the selected class
        cursor.execute("""
            SELECT g.group_id, g.group_name
            FROM group_members gm
            JOIN Groups g ON gm.group_id = g.group_id
            WHERE gm.user_id = ? AND gm.class_id = ?
        """, (user_id, class_id))
        group = cursor.fetchone()

        if group:
            group_id = group['group_id']
            return redirect(url_for('confirm_group', class_id=class_id, group_id=group_id))

    conn.close()
    return render_template('select_class.html', classes=classes)

@app.route('/confirm_group/<class_id>/<group_id>', methods=['GET', 'POST'])
def confirm_group(class_id, group_id):
    if "user_id" not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor()

    # Get group and class information
    cursor.execute("""
        SELECT g.group_name, c.class_name
        FROM Groups g
        JOIN Classes c ON g.class_id = c.class_id
        WHERE g.group_id = ? AND c.class_id = ?
    """, (group_id, class_id))
    group_info = cursor.fetchone()

    conn.close()

    if request.method == 'POST':
        return redirect(url_for('evaluate_group', class_id=class_id, group_id=group_id))

    return render_template('confirm_group.html', group_name=group_info['group_name'], class_name=group_info['class_name'], class_id=class_id, group_id=group_id)

@app.route('/evaluate_group/<class_id>/<group_id>', methods=['GET', 'POST'])
def evaluate_group(class_id, group_id):
    if "user_id" not in session:
        return redirect(url_for('login'))

    user_id = session["user_id"]
    conn = get_db_connection()
    cursor = conn.cursor()

    evaluator_id = session.get('user_id')

    # Fetch self-evaluation data
    cursor.execute("""
        SELECT * FROM Evaluate_self WHERE evaluator_id = ?
    """, (user_id,))
    evaluation_self_data = cursor.fetchone()

    if request.method == 'POST' and request.form:
        ratings = request.form.getlist('rating')
        comments = request.form.getlist('comment')
        evaluated_ids = request.form.getlist('evaluated_id')

        # Loop through each groupmate to insert/update evaluation
        for i, evaluated_id in enumerate(evaluated_ids):
            rating = float(ratings[i])  # Ensure the rating is a float
            comment = comments[i]

            # Check if evaluation already exists
            cursor.execute("""
                SELECT * FROM Evaluation
                WHERE evaluator_id = ? AND evaluated_id = ? AND class_id = ? AND group_id = ?
            """, (user_id, evaluated_id, class_id, group_id))
            evaluation = cursor.fetchone()

            if evaluation:
                # Update existing evaluation
                cursor.execute("""
                    UPDATE Evaluation
                    SET rating = ?, comments = ?, id_edited = 1
                    WHERE evaluator_id = ? AND evaluated_id = ? AND class_id = ? AND group_id = ?
                """, (rating, comment, user_id, evaluated_id, class_id, group_id))
            else:
                # Insert new evaluation
                cursor.execute("""
                    INSERT INTO Evaluation (evaluator_id, evaluated_id, class_id, group_id, rating, comments)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (user_id, evaluated_id, class_id, group_id, rating, comment))

        conn.commit()

        # Handle self-reflection comments
        comments_self01 = request.form['comments_self01']
        comments_self02 = request.form['comments_self02']
        comments_self03 = request.form['comments_self03']
        comments_self04 = request.form['comments_self04']

        if evaluation_self_data:
            # Update existing self-evaluation
            cursor.execute("""
                UPDATE Evaluate_self
                SET comments_self01 = ?, comments_self02 = ?, comments_self03 = ?, comments_self04 = ?
                WHERE evaluator_id = ?
            """, (comments_self01, comments_self02, comments_self03, comments_self04, user_id))
        else:
            # Insert new self-evaluation
            cursor.execute("""
                INSERT INTO Evaluate_self (evaluator_id, comments_self01, comments_self02, comments_self03, comments_self04)
                VALUES (?, ?, ?, ?, ?)
            """, (user_id, comments_self01, comments_self02, comments_self03, comments_self04))

        conn.commit()

        # Calculate adjusted ratings
        cursor.execute("SELECT COUNT(*) FROM group_members WHERE class_id = ? AND group_id = ?", (class_id, group_id))
        num_students = cursor.fetchone()[0]

        # Sum of ratings for each evaluated student
        cursor.execute("SELECT evaluated_id, SUM(rating) as sum_rating FROM Evaluation WHERE class_id = ? AND group_id = ? GROUP BY evaluated_id", (class_id, group_id))
        ratings_sum = cursor.fetchall()

        sum_ratings_dict = {row['evaluated_id']: row['sum_rating'] for row in ratings_sum}

        # Fetch individual ratings
        cursor.execute("SELECT evaluator_id, evaluated_id, rating FROM Evaluation WHERE class_id = ? AND group_id = ?", (class_id, group_id))
        individual_ratings = cursor.fetchall()

        adjusted_ratings = {}
        for r in individual_ratings:
            evaluator_id = r['evaluator_id']
            evaluated_id = r['evaluated_id']
            rating = r['rating']
            sum_rating = sum_ratings_dict[evaluated_id]
            adjusted_rating = (rating / sum_rating) * 3 * num_students
            adjusted_ratings[(evaluator_id, evaluated_id)] = adjusted_rating

            cursor.execute("UPDATE Evaluation SET adjusted_rating = ? WHERE evaluator_id = ? AND evaluated_id = ? AND class_id = ? AND group_id = ?",
                           (adjusted_rating, evaluator_id, evaluated_id, class_id, group_id))

        conn.commit()

        # Fetch student names for adjusted ratings
        student_names = {}
        for (evaluator_id, evaluated_id), adjusted_rating in adjusted_ratings.items():
            cursor.execute("SELECT name FROM Users WHERE user_id = ?", (evaluated_id,))
            student_name = cursor.fetchone()['name']
            student_names[evaluated_id] = student_name

        conn.close()
        return render_template('rating_result.html', adjusted_ratings=adjusted_ratings, class_id=class_id, group_id=group_id, current_user_id=user_id, student_names=student_names)
    else:
        try:
            # Get evaluation information
            print("group_id:", group_id)
            print("class_id:", class_id)
            print("user_id:", user_id)
            cursor.execute("""
                SELECT *
                FROM Evaluation
                WHERE Evaluation.group_id = ? AND Evaluation.class_id = ? AND Evaluation.evaluator_id= ?
            """, (group_id, class_id, user_id))
            evaluation_data = cursor.fetchall()

            # Print evaluation data for debugging
            print("Evaluation Data:", evaluation_data)

            # Get groupmates information
            cursor.execute("""
                SELECT u.user_id, u.name
                FROM group_members gm
                JOIN Users u ON gm.user_id = u.user_id
                WHERE gm.group_id = ? AND gm.class_id = ? AND u.user_id != ?
            """, (group_id, class_id, user_id))
            groupmates = cursor.fetchall()

            # Get group and class information
            cursor.execute("""
                SELECT g.group_name, c.class_name
                FROM Groups g
                JOIN Classes c ON g.class_id = c.class_id
                WHERE g.group_id = ? AND c.class_id = ?
            """, (group_id, class_id))
            group_info = cursor.fetchone()

            # Add the current user to the list of groupmates for self-evaluation
            cursor.execute("SELECT name FROM Users WHERE user_id = ?", (user_id,))
            user_name = cursor.fetchone()['name']
            groupmates.append({'user_id': user_id, 'name': user_name})

            conn.close()

            return render_template('evaluate_group.html', groupmates=groupmates, class_id=class_id, group_id=group_id, group_name=group_info['group_name'], class_name=group_info['class_name'], evaluation_data=evaluation_data, evaluation_self_data=evaluation_self_data)
        except Exception as e:
            # Print error message for debugging
            print("Error:", e)
    
@app.route('/rating_result', methods=['POST'])
def rating_result():
    # Handle the form submission from the rating results page
    action = request.form['action']
    class_id = request.form['class_id']
    group_id = request.form['group_id']

    if action == 'proceed':
        flash('Rating submitted successfully!', 'success')
        return redirect(url_for('evaluate_group', class_id=class_id, group_id=group_id))
    elif action == 're_rate':
        return redirect(url_for('evaluate_group', class_id=class_id, group_id=group_id))




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
        confirm_password = request.form['confirm_password']
        class_id = request.form['class_id']
        group_id = request.form['group_id']

        if not name or not password or not confirm_password:
          flash('All fields are required', 'error')
          return redirect(url_for('signup_invited'))
    
        if password != confirm_password:
          flash('Passwords do not match', 'error')
          return redirect(url_for('signup_invited'))
    

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

                cursor.execute("INSERT INTO Student_class (student_id, class_id) VALUES (?, ?)",
                            (existing_user_id, class_id))

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

                cursor.execute("INSERT INTO Student_class (student_id, class_id) VALUES (?, ?)",
                            (user_id, class_id))

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
    confirm_password = request.form['confirm_password']
    app_password = request.form['app_password']
    email = request.form['email']
    role = request.form['role']
    class_id = request.form.get('class_id')
    group_id = request.form.get('group_id')

    if not name or not password or not confirm_password:
        flash('All fields are required', 'error')
        return redirect(url_for('signup'))
    
    if password != confirm_password:
        flash('Passwords do not match', 'error')
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
        cursor.execute("DELETE FROM Student_class WHERE class_id = ?", (class_id,))
        cursor.execute("DELETE FROM Class_lecturers WHERE class_id = ?", (class_id,))
        cursor.execute("DELETE FROM Groups WHERE class_id = ?", (class_id,))
        cursor.execute("DELETE FROM group_members WHERE class_id = ?", (class_id,))
        cursor.execute("DELETE FROM Evaluation WHERE class_id = ?", (class_id))
        conn.commit()
        flash('Class successfully remove', 'success')
    except Exception as e:
        conn.rollback()
        flash(f'Error removing class: {str(e)}', 'danger')
    finally:
        conn.close()
    return redirect(url_for('class_list'))

@app.route('/drop_class/<class_id>')
def drop_class(class_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # Delete Class_lecturers from the database
        cursor.execute("DELETE FROM Class_lecturers WHERE class_id = ?", (class_id,))
        conn.commit()
        flash('Class successfully drop', 'success')
    except Exception as e:
        conn.rollback()
        flash(f'Error dropping class: {str(e)}', 'danger')
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
            SELECT Users.user_id, Users.name, Users.email, Classes.class_name, Groups.group_id
            FROM Users
            LEFT JOIN group_members ON Users.user_id = group_members.user_id
            LEFT JOIN Classes ON group_members.class_id = Classes.class_id
            LEFT JOIN Groups ON group_members.group_id = Groups.group_id
            WHERE Classes.class_id IN (
                SELECT class_id FROM Class_lecturers WHERE lecturer_id = ?
            )
            AND Users.user_id IN (
                SELECT user_id FROM User_roles WHERE role_id = (
                    SELECT role_id FROM Roles WHERE role_name = 'student'
                )
            )
        """, (lecturer_id,))
        #GROUP BY Users.user_id, Users.name, Users.email
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
        
@app.route('/delete_student/<int:user_id>/<int:group_id>')
def delete_student(user_id, group_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # Delete student from the database
        cursor.execute("DELETE FROM group_members WHERE user_id = ? AND group_id = ?", (user_id, group_id))
        cursor.execute("DELETE FROM Evaluation WHERE evaluator_id = ? AND group_id = ?", (user_id, group_id))
        cursor.execute("DELETE FROM Student_class WHERE student_id = ?", (user_id,))
        conn.commit()
        flash('Student successfully removed from class', 'success')
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
        cursor.execute("""
                    SELECT Classes.class_id, Classes.class_name
                    FROM Class_lecturers
                    INNER JOIN Classes ON Class_lecturers.class_id = Classes.class_id
                    WHERE Class_lecturers.lecturer_id = ?
                """, (user_id,))
        classes = cursor.fetchall()  # Fetch all classes

        # Fetch groups from the database (you may need to filter by the selected class)
        cursor.execute("SELECT group_id, group_name FROM Groups")
        groups = cursor.fetchall()

        conn.close()

        return render_template('add_students.html', lecturer_email= lecturer_email , classes=classes, groups=groups)
    else:
        return redirect(url_for('login'))

@app.route('/upload_students', methods=['GET', 'POST'])
def upload_students():
    lecturer_id = session.get("user_id")  # Use session.get() to avoid KeyError if user_id is not present
    if lecturer_id:
        print(f'Lecturer ID:', lecturer_id)
        if request.method == 'POST':
            if 'file' not in request.files:
                flash('No file part', 'danger')
                return redirect(request.url)
            file = request.files['file']
            if file.filename == '':
                flash('No selected file', 'danger')
                return redirect(request.url)
            if file:
                try:
                    # Read the CSV file
                    df = pd.read_csv(file)

                    conn = get_db_connection()
                    cursor = conn.cursor()

                    for index, row in df.iterrows():
                        name = row['name']
                        email = row['email']
                        password = row['password']
                        class_id = row['class_id']
                        class_name = row['class_name']

                        print(f'Processing row: Name={name}, Email={email}, Class ID={class_id}, Class Name={class_name}')

                        hashed_password = hash_password(password)

                        # Check if the user already exists
                        cursor.execute("SELECT * FROM Users WHERE email = ?", (email,))
                        existing_user = cursor.fetchone()

                        if existing_user:
                            user_id = existing_user['user_id']
                        else:
                            # Insert the user into the Users table
                            cursor.execute("INSERT INTO Users (name, email, password) VALUES (?, ?, ?)",
                                        (name, email, hashed_password))
                            user_id = cursor.lastrowid

                        print(f'User ID: {user_id}')

                        # Check if the user already has the student role
                        cursor.execute("SELECT user_id FROM User_roles WHERE user_id = ? AND role_id = (SELECT role_id FROM Roles WHERE role_name = 'student')", (user_id,))
                        existing_student_role = cursor.fetchone()

                        if not existing_student_role:
                            # Assign the student role
                            cursor.execute("INSERT INTO User_roles (user_id, role_id) VALUES (?, (SELECT role_id FROM Roles WHERE role_name = 'student'))", (user_id,))

                        # Check if the class already exists
                        cursor.execute("SELECT class_id FROM Classes WHERE class_id = ?", (class_id,))
                        existing_class = cursor.fetchone()

                        if existing_class:
                            class_id = existing_class['class_id']
                        else:
                            # Insert the class into the Classes table
                            cursor.execute("INSERT INTO Classes (class_id, class_name) VALUES (?, ?)", (class_id, class_name))

                        print(f'Class ID: {class_id}')

                        # Check if the class-lecturer association already exists
                        cursor.execute("SELECT * FROM Class_lecturers WHERE class_id = ? AND lecturer_id = ?", (class_id, lecturer_id))
                        existing_association = cursor.fetchone()

                        if not existing_association:
                            # Associate the class with the lecturer
                            cursor.execute("INSERT INTO Class_lecturers (class_id, lecturer_id) VALUES (?, ?)", (class_id, lecturer_id))

                        # Check if the student is already assigned to this class
                        cursor.execute("SELECT * FROM Student_class WHERE class_id = ? AND student_id = ?", (class_id, user_id))
                        existing_assignment = cursor.fetchone()

                        if not existing_assignment:
                            # Assign the student to the class
                            cursor.execute("INSERT INTO Student_class (class_id, student_id) VALUES (?, ?)", (class_id, user_id))

                    conn.commit()
                    conn.close()
                    flash('Students imported successfully!', 'success')
                except Exception as e:
                    flash(f'Error importing students: {str(e)}', 'danger')

                return redirect(url_for('upload_students'))
        return render_template('import_students.html')
    else:
        return 'No user Logged in'
    
@app.route('/get_groups_stu/<class_id>', methods=['GET'])
def get_groups_stu(class_id):
    user_id = session.get('user_id')

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT Groups.group_id, Groups.group_name
        FROM Groups
        INNER JOIN group_members ON Groups.group_id = group_members.group_id
        WHERE group_members.user_id = ? AND group_members.class_id = ?
    """, (user_id, class_id))
    
    groups = cursor.fetchall()
    conn.close()

    return jsonify({'groups': [{'group_id': row['group_id'], 'group_name': row['group_name']} for row in groups]})

@app.route('/get_group_mates/<group_id>/<class_id>', methods=['GET'])
def get_group_mates(group_id, class_id):
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'User not logged in'}), 401

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT Users.user_id, Users.name
        FROM Users
        INNER JOIN group_members ON Users.user_id = group_members.user_id
        WHERE group_members.group_id = ? AND group_members.class_id = ?
    """, (group_id, class_id))
    students = cursor.fetchall()
    conn.close()

    return jsonify({'students': [{'user_id': student['user_id'], 'name': student['name']} for student in students]})

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
            SELECT Users.user_id, Users.name, Classes.class_id, Classes.class_name, Groups.group_id, Groups.group_name 
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
    
@app.route('/add_group', methods=['POST', 'GET'])
def add_group():
    if request.method == 'POST':
        lecturer_id = session.get('user_id')
        if lecturer_id:
            class_id = request.form['class_id']
            group_name = request.form['group_name']

            # Check if class already exists
            conn = get_db_connection()
            cursor = conn.cursor()

            # Insert new class into the database
            cursor.execute("INSERT INTO Groups (class_id, group_name) VALUES (?, ?)", (class_id, group_name))
            conn.commit()

            flash('Group created successfully', 'success')
        
        else:
            return redirect(url_for('login'))

    # Regardless of POST or GET, fetch the classes
    lecturer_id = session.get('user_id')
    if lecturer_id:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
                    SELECT Classes.class_id, Classes.class_name
                    FROM Class_lecturers
                    INNER JOIN Classes ON Class_lecturers.class_id = Classes.class_id
                    WHERE Class_lecturers.lecturer_id = ?
                """, (lecturer_id,))
        classes = cursor.fetchall()  # Fetch all classes
        conn.close()
        
        return render_template('add_group.html', classes=classes)
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
                    SELECT Users.user_id, Users.name, Classes.class_id, Classes.class_name, Groups.group_name 
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
    
@app.route('/delete_group/<int:group_id>/<string:class_id>')
def delete_group(group_id, class_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM group_members WHERE group_id = ? AND class_id = ?", (group_id, class_id))
        cursor.execute("DELETE FROM Evaluation WHERE group_id = ?", (group_id))
        conn.commit()
        flash('Student successfully removed', 'success')
    except Exception as e:
        conn.rollback()
        flash(f'Error deleting group: {str(e)}', 'danger')
    finally:
        conn.close()
    return redirect(url_for('group_list'))

@app.route('/logout')
def logout():
    session.pop("user_id" , None)
    return redirect(url_for("login"))

if __name__ == '__main__':
    app.run(debug=True)