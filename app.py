from flask import Flask, render_template, request, make_response
app = Flask(__name__)
import bcrypt
import jwt
import subprocess

from flask_wtf.csrf import CSRFProtect
from flask_wtf import FlaskForm
from wtforms import StringField
from wtforms.validators import DataRequired

app.secret_key = 'very secret'
csrf = CSRFProtect()
csrf.init_app(app)

#in real life, this would be random and stored in an environment variable
SECRET_KEY = "this_is_a_secret"

#hacky, maybe fix this
passwords = {}
salts = {}
tfas = {}

class RegisterForm(FlaskForm):
  uname = StringField('Username', validators=[DataRequired()])
  pword = StringField('Password', validators=[DataRequired()])
  tfa = StringField('2fa')

class SpellCheckForm(FlaskForm):
  inputtext = StringField('Input text')

def add_pass(username, password, tfa):
  salt = bcrypt.gensalt()
  salts[username] = salt
  passwords[username] = bcrypt.hashpw(password.encode('utf-8'), salt)
  tfas[username] = tfa

def check_pass(username, password):
  if (username in passwords):
    salt = salts[username]
    if (passwords[username] == bcrypt.hashpw(password.encode('utf-8'), salt)):
      return True
  return False

def check_tfa(username, tfa):
  if (username in passwords):
    if (tfas[username] == tfa):
      return True
  return False

@app.route("/")
@app.route("/register", methods=["GET", "POST"])
def register():
  form = RegisterForm()
  if form.validate_on_submit():
    username = form.uname.data
    password = form.pword.data
    second_factor = form.tfa.data
    if username in passwords or password == "":
      return render_template("register.html", success="failure", form=form)
    add_pass(username, password, second_factor)
    return render_template("register.html", success="success", form=form)
  else:
    return render_template("register.html", success="", form=form)


@app.route("/login", methods=["GET", "POST"])
def login():
  form = RegisterForm()
  if form.validate_on_submit():
    username = form.uname.data
    password = form.pword.data
    second_factor = form.tfa.data
    print(second_factor)
    if (not check_pass(username, password)):
      return render_template("login.html", result = "Incorrect", form=form)
    if (not check_tfa(username, second_factor)):
      return render_template("login.html", result = "Two-factor failure", form=form)
    #session management
    token = jwt.encode({'userid': username}, SECRET_KEY, algorithm='HS256')
    resp = make_response(render_template("login.html", result="success", form=form))
    resp.set_cookie("session-token", token)
    return resp
  else:
    return render_template("login.html", result = "", form=form)

@app.route("/spell_check", methods=["GET", "POST"])
def spell_check_page():
  form = SpellCheckForm()
  if not request.cookies.get("session-token"):
    return "Not logged in"
  token = request.cookies.get("session-token")
  user = jwt.decode(token, SECRET_KEY, algorithms='HS256')["userid"]
  if user not in passwords:
    return "Not logged in"

  if form.validate_on_submit():
    text = form.inputtext.data
    f = open("file.txt", "w")
    f.write(text)
    f.close()
    output = subprocess.run(["./a.out", "wordlist.txt", "file.txt"], capture_output = True)
    return render_template("spell_check.html", textout = text, misspelled = output.stdout, form=form)
  else:
    return render_template("spell_check.html", textout = "", misspelled = "", form=form)


if __name__ == "__main__":
  app.run()
