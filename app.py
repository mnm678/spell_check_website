from flask import Flask, render_template, request, make_response
app = Flask(__name__)
import bcrypt
import jwt
import subprocess

from flask_wtf.csrf import CSRFProtect
from flask_wtf import FlaskForm
from wtforms import StringField
from wtforms.validators import DataRequired
from flask_login import LoginManager, UserMixin, login_required, login_user

app.secret_key = 'very secret'
csrf = CSRFProtect()
csrf.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
@login_manager.user_loader
def load_user(user_id):
  print("load")
  print(user_id)
  if (user_id in users):
    return users[user_id]
  return None

#in real life, this would be random and stored in an environment variable
SECRET_KEY = "this_is_a_secret"

users = {}

class User(UserMixin):
  id = None
  username = None
  tfa = ""
  password = None
  def __init__(self, username, tfa):
    self.username = username
    self.tfa = tfa
    self.id = username

  def set_password(self, password):
    self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
  def check_password(self, password):
    return bcrypt.checkpw(password.encode('utf-8'), self.password)
  def check_tfa(self, tfa):
    return self.tfa == tfa
  def __repr__(self):
    return '<User {}>'.format(self.username)

class RegisterForm(FlaskForm):
  uname = StringField('Username', validators=[DataRequired()])
  pword = StringField('Password', validators=[DataRequired()])
  tfa = StringField('2fa')

class SpellCheckForm(FlaskForm):
  inputtext = StringField('Input text')

@app.route("/")
@app.route("/register", methods=["GET", "POST"])
def register():
  form = RegisterForm()
  if form.validate_on_submit():
    username = form.uname.data
    password = form.pword.data
    second_factor = form.tfa.data
    if username in users or password == "":
      return render_template("register.html", success="failure", form=form)
    user = User(username=username, tfa=second_factor)
    user.set_password(password)
    users[username] = user
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

    if username not in users:
      return render_template("login.html", result = "Incorrect", form=form)
    user = users[username]

    if (not user.check_password(password)):
      return render_template("login.html", result = "Incorrect", form=form)
    if (not user.check_tfa(second_factor)):
      return render_template("login.html", result = "Two-factor failure", form=form)

    #session management
    login_user(user)
    resp = make_response(render_template("login.html", result="success", form=form))
    return resp
  else:
    return render_template("login.html", result = "", form=form)

@app.route("/spell_check", methods=["GET", "POST"])
@login_required
def spell_check_page():
  form = SpellCheckForm()

  if form.validate_on_submit():
    text = form.inputtext.data
    f = open("file.txt", "w")
    f.write(text)
    f.close()
    output = subprocess.run(["./a.out", "wordlist.txt", "file.txt"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return render_template("spell_check.html", textout = text, misspelled = output.stdout, form=form)
  else:
    return render_template("spell_check.html", textout = "", misspelled = "", form=form)


if __name__ == "__main__":
  app.run()
