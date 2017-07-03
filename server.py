from flask import Flask, render_template, redirect, request, session, flash
from mysqlconnection import MySQLConnector
from flask_bcrypt import Bcrypt
import re

app = Flask(__name__)
app.secret_key = "thisIsASecret"
bcrypt = Bcrypt(app)
mysql = MySQLConnector(app, 'wall')
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9\.\+_-]+@[a-zA-Z0-9\._-]+\.[a-zA-Z]*$')
ALL_LETTERS = re.compile(r'^[a-zA-Z]+$')

@app.route('/')
def indext():
    return render_template('index.html')

@app.route('/wall')
def wall():
    query = 'SELECT * FROM users WHERE id = :id LIMIT 1'
    data = {'id': session['id']}
    user = mysql.query_db(query, data)

    msg_query = "SELECT * FROM messages ORDER BY messages.created_at"
    messages = mysql.query_db(msg_query)

    comment_query = "SELECT * FROM comments"
    comments = mysql.query_db(comment_query)

    usr_query = "SELECT * FROM users"
    users = mysql.query_db(usr_query)

    return render_template('wall.html', current_user = user[0], messages = messages, comments = comments, users=users)

@app.route('/post_message', methods=['POST'])
def post_message():
    query = 'INSERT INTO messages (user_id, message, created_at, updated_at) VALUES (:user_id, :message, NOW(), NOW())'
    data = {
        'user_id': session['id'],
        'message': request.form['message']
    }
    mysql.query_db(query, data)
    return redirect('/wall')

@app.route('/post_comment', methods=['POST'])
def post_comment():
    query = 'INSERT INTO comments (user_id, message_id, comment, created_at, updated_at) VALUES (:user_id, :message_id, :comment, NOW(), NOW())'
    data = {
        'user_id': session['id'],
        'message_id': request.form['msg_id'],
        'comment': request.form['comment']
    }
    mysql.query_db(query, data)
    return redirect('/wall')

@app.route('/validate', methods=['POST'])
def validate():
    if request.form['submit'] == 'Register':
        # Validate First Name Value
        if len(request.form['first_name']) >= 2 and ALL_LETTERS.match(request.form['first_name']):
            first_name = request.form['first_name']
        else:
            flash('User first name must be at least 2 characters and only non-numeric values.')

        # Validate Last Name Value
        if len(request.form['last_name']) >= 2 and ALL_LETTERS.match(request.form['last_name']):
            last_name = request.form['last_name']
        else:
            flash('User last name must be at least 2 characters and only non-numeric values.')

        # Validate Email Value
        if len(request.form['email']) > 0 and EMAIL_REGEX.match(request.form['email']):
            email = request.form['email']
        else:
            flash('Please enter a valid email address.')

        # Validate Password Value
        if len(request.form['pw']) >= 8:
            pw_hash = bcrypt.generate_password_hash(request.form['pw'])
        else:
            flash('Password must be at least 8 characters long.')

        # Validate Password Confirmation Value
        if request.form['pw'] != request.form['pw_confirm']:
            flash('Passwords must match.')

        # Route based on Flashes
        if '_flashes' in session:
            return redirect('/')
        else:
            query = "INSERT INTO users (first_name, last_name, email, password, created_at, updated_at) VALUES (:first_name, :last_name, :email, :password, NOW(), NOW())"
            data = {
                'first_name': first_name,
                'last_name': last_name,
                'email': email,
                'password': pw_hash
            }
            mysql.query_db(query, data)

            session_query = 'SELECT id FROM users WHERE email = :email LIMIT 1'
            session_id = mysql.query_db(session_query, data)
            session['id'] = session_id[0]['id']

            return redirect('/wall')

    elif request.form['submit'] == 'Login':
        query = 'SELECT * FROM users WHERE email = :email'
        data = {'email': request.form['email']}
        user = mysql.query_db(query, data)

        if bcrypt.check_password_hash(user[0]['password'], request.form['pw']):
            userId = mysql.query_db("SELECT id FROM users WHERE email = :email LIMIT 1", data)
            session['id'] = userId[0]['id']
            return redirect('/wall')
        else:
            flash('Invalid Password')
            return redirect('/')


app.run(debug=True)
