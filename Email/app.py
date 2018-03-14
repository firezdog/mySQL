from flask import Flask, request, redirect, render_template, session, flash
from mysqlconnection import MySQLConnector
import re

app = Flask(__name__)
mysql = MySQLConnector(app,'emails')
app.secret_key = "..."
emailRegex = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')

@app.before_first_request
def init():
    session["display"] = "display-off"

@app.route('/', methods=["POST","GET"])
def index():
    if request.method == "POST":
        if emailRegex.match(request.form["email"]):
            session["entered"] = request.form["email"]
            query = "INSERT INTO emails (email, date_created) VALUES (:email, NOW())"
            data = {
                'email': request.form['email'],
            }
            mysql.query_db(query, data)
            return redirect("/success")
        else:
            session["display"] = "display-on"
            return redirect("/")
    else:
        return render_template("index.html", display=session["display"])

@app.route('/success')
def success():
    emails = mysql.query_db("SELECT * FROM emails")
    return render_template("success.html", emails=emails, entered=session["entered"])
app.run(debug=True)