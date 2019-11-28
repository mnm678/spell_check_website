from flask import Flask, render_template, request, make_response
app = Flask(__name__)
import bcrypt
import jwt
import subprocess

from flask_wtf.csrf import CSRFProtect
from flask_wtf import FlaskForm
from wtforms import StringField
from wtforms.validators import DataRequired
from flask_login import LoginManager, UserMixin, login_required, login_user, current_user, logout_user

from flask_sqlalchemy import SQLAlchemy
import datetime
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
db = SQLAlchemy(app)

app.secret_key = 'very secret'
csrf = CSRFProtect()
csrf.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
@login_manager.user_loader
def load_user(user_id):
  return User.query.get(user_id)

#in real life, this would be random and stored in an environment variable
SECRET_KEY = "this_is_a_secret"

class User(db.Model):
  __tablename__ = 'user'

  username = db.Column(db.String, primary_key=True)
  password = db.Column(db.String)
  tfa = db.Column(db.String)
  authenticated = db.Column(db.Boolean, default=False)

  def set_password(self, password):
    self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
  def check_password(self, password):
    return bcrypt.checkpw(password.encode('utf-8'), self.password)
  def check_tfa(self, tfa):
    return self.tfa == tfa
  def is_active(self):
    return True
  def get_id(self):
    return self.username
  def is_authenticated(self):
    return authenticated
  def is_anonymous(self):
    return False

class SpellRecord(db.Model):
  __tablename__ = 'record'

  record_id = db.Column(db.Integer, primary_key = True, autoincrement = True)
  user = db.Column(db.String)
  u_query = db.Column(db.String)
  result = db.Column(db.String)

class LoginRecord(db.Model):
  __tablename__ = 'login'

  login_id = db.Column(db.Integer, primary_key = True, autoincrement = True)
  user = db.Column(db.String)
  login_time = db.Column(db.DateTime)
  logout_time = db.Column(db.DateTime)


db.create_all()
#add admin user
admin = User(username='admin', tfa='12345678901')
admin.set_password("Administrator@1")
db.session.add(admin)
db.session.commit()

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

    user = User.query.get(username)

    if user or password == "":
      return render_template("register.html", success="failure", form=form)
    user = User(username=username, tfa=second_factor)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
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

    user = User.query.get(username)

    if not user:
      return render_template("login.html", result = "Incorrect", form=form)

    if (not user.check_password(password)):
      return render_template("login.html", result = "Incorrect", form=form)
    if (not user.check_tfa(second_factor)):
      return render_template("login.html", result = "Two-factor failure", form=form)

    #session management
    user.authenticated = True
    db.session.add(user)
    login_record = LoginRecord(user=user.username, login_time=datetime.datetime.now())
    db.session.add(login_record)
    db.session.commit()
    login_user(user)
    resp = make_response(render_template("login.html", result="success", form=form))
    return resp
  else:
    return render_template("login.html", result = "", form=form)

@app.route("/logout", methods=["GET"])
def logout():
  user = current_user
  user.authenticated = False
  db.session.add(user)
  login_records = LoginRecord.query.filter_by(user=user.username).order_by(LoginRecord.login_time).all()
  login_record = login_records[-1]
  login_record.logout_time = datetime.datetime.now()
  db.session.add(login_record)
  db.session.commit()
  logout_user()
  return "Success"

@app.route("/spell_check", methods=["GET", "POST"])
@login_required
def spell_check_page():
  user = current_user
  form = SpellCheckForm()

  if form.validate_on_submit():
    text = form.inputtext.data
    f = open("file.txt", "w")
    f.write(text)
    f.close()
    output = subprocess.run(["./a.out", "wordlist.txt", "file.txt"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    record = SpellRecord(user = user.username, u_query = text, result = output.stdout)
    db.session.add(record)
    db.session.commit()
    return render_template("spell_check.html", textout = text, misspelled = output.stdout, form=form)
  else:
    return render_template("spell_check.html", textout = "", misspelled = "", form=form)


class HistoryForm(FlaskForm):
  userquery = StringField('User')

@app.route("/history", methods=["GET", "POST"])
@login_required
def get_history():
  form = HistoryForm()
  username = current_user.username
  if username == "admin":
    if form.validate_on_submit():
      query_user = form.userquery.data
      username = query_user
      #fallthrough to showing the records
    else:
      return render_template("admin_history.html", form=form)

  queries = SpellRecord.query.filter_by(user = username).all()
  count = SpellRecord.query.filter_by(user = username).count()
  return render_template("history.html", numqueries = count, records = queries)

@app.route("/history/query<n>")
@login_required
def show_record(n):
  username = current_user.username
  query = SpellRecord.query.get(n)
  if (username == "admin" or username == query.user):
    return render_template("record.html", query=query)
  return "Unauthorized"

class LoginHistoryForm(FlaskForm):
  userid = StringField('User')

@app.route("/login_history", methods=["GET", "POST"])
@login_required
def view_history():
  form = LoginHistoryForm()
  if current_user.username == "admin":
    if form.validate_on_submit():
      user = form.userid.data
      logins = LoginRecord.query.filter_by(user=user).all()
      return render_template("login_history.html", form=form, logins=logins)
    else:
      return render_template("login_history.html", form=form)
  else:
    return "Unauthorized"


if __name__ == "__main__":
  app.run()
