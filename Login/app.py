from flask import Flask, request, redirect, render_template, session, flash
from mysqlconnection import MySQLConnector
import re
import os, binascii, md5

app = Flask(__name__)
mysql = MySQLConnector(app,'users')
app.secret_key = "..."
emailRegex = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
spaceRegex = re.compile(r'^\s*$')

@app.before_first_request
def init():
    #for tests
    session["user"] = 1
    #session["user"] = 0

@app.route('/')
def index():
    if session["user"] == 0:
        return render_template("index.html")
    else:
        return redirect('/success')

@app.route('/register', methods=["POST"])
def register():
    validations = {
        'name_length': False,
        'name_letters': False,
        'email': False,
        'unique': False,
        'password_length': False,
        'password_conf': False
    }
    valid = True
    validations['name_length'], validations['name_letters'] = checkNames(request.form['first_name'], request.form['last_name'])
    validations['email'], validations['unique'] = checkEmail(request.form['reg_email'])
    validations['password_length'], validations['password_conf'] = checkPassword(request.form['password'], request.form['confirm_password'])
    for test in validations:
        if validations[test] == False:
            valid = False
    if not valid:
        generateErrors(validations)
        return redirect('/')
    else:
        salt = binascii.b2a_hex(os.urandom(15))
        hashed_password = md5.new(request.form['password'] + salt).hexdigest()
        query = "INSERT INTO users (first_name, last_name, email, password, salt, created_at) VALUES (:first_name, :last_name, :email, :password, :salt, now())"
        data = {
            'first_name': request.form['first_name'],
            'last_name': request.form['last_name'],
            'email': request.form['reg_email'],
            'password': hashed_password,
            'salt': salt
        }
        mysql.query_db(query, data)
        flash("Registration successful. Please log-in.", "login")
        return redirect('/')

def checkPassword(password, confirmation):
    length = False
    same = False
    if len(password) > 7:
        length = True
    if password == confirmation:
        same = True
    return length, same

def checkEmail(email):
    form = False
    unique = False
    if emailRegex.match(email): 
        form = True
    query = "select * from users where email = :email"
    data = {'email': email}
    user = mysql.query_db(query, data)
    if len(user) == 0:
        unique = True
    return form, unique


def checkNames(first_name, last_name):
    length = False
    letters = False
    if len(first_name) > 2 and len(last_name) > 2:
        length = True
    if first_name.isalpha() and last_name.isalpha():
        letters = True
    return length, letters

def generateErrors(validations):
    if not validations['name_length']:
        flash("First and last name are required and must be longer than 2 characters.", "registration")
    elif not validations['name_letters']:
        flash("First and last name may not contain non-alphabetical characters.", "registration")
    if not validations['email']:
        flash("You must enter a valid e-mail address.", "registration")
    elif not validations['unique']:
        flash("Email address already in use.", "registration")
    if not validations['password_length']:
        flash("Password must be at least 8 characters.", "registration")
    elif not validations['password_conf']:
        flash("Password and confirmation do not match. Please re-enter password.", "registration")

@app.route('/login', methods=["POST"])
def login():
    if request.method == "POST":
        query = "select * from users where email = :login"
        data = {'login': request.form['login']}
        user = mysql.query_db(query, data)
        if len(user) == 1: 
            hashed_password = md5.new(request.form['password'] + user[0]['salt']).hexdigest()
            if hashed_password == user[0]['password']:
                print("password match")
                session['user'] = user[0]['id']
                return redirect('/success')
            else:
                flash("Incorrect password.", "login")
                return redirect("/")
        else: 
            flash("User not found in database.", "login")
            return redirect('/')

@app.route('/success')
def success():
    if session['user'] > 0:
        query = "select users.first_name from users where users.id = {}".format(session['user'])
        name_result = mysql.query_db(query)
        name = name_result[0]['first_name']
        query = "select users.first_name, users.last_name, messages.id, messages.created_at, messages.message from users join messages on users.id = messages.user_id"
        messages = mysql.query_db(query)
        query = "select users.first_name, users.last_name, comments.created_at, comments.comment, comments.message_id from users join comments on users.id = comments.user_id"
        comments = mysql.query_db(query)
        return render_template("success.html", name=name, messages = messages, comments=comments)
    else:
        return redirect('/')

@app.route('/message', methods=["POST"])
def postMessage():
    if not spaceRegex.match(request.form['message']):
        query = "INSERT INTO messages (user_id, message, created_at, updated_at) VALUES (:user, :message, now(), now())"
        data = {
            'user': session['user'],
            'message': request.form['message']
        }
        mysql.query_db(query, data)
    else:
        flash("No message entered.")
    return redirect('/success')

@app.route('/comment', methods=["POST"])
def postComment():
    if not spaceRegex.match(request.form['comment']):
        print request.form
        query = "INSERT INTO comments (user_id, message_id, comment, created_at, updated_at) VALUES (:user, :message, :comment, now(), now())"
        data = {
            'user': session['user'],
            'message': request.form['message'],
            'comment': request.form['comment']
        }
        mysql.query_db(query, data)
    else:
        flash("No comment entered.")
    return redirect('/success')

@app.route('/logout')
def logout():
    session['user'] = 0
    return redirect('/')

app.run(debug=True)