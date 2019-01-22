from flask_login import LoginManager, login_user, current_user, login_required, logout_user, UserMixin
from flask import Flask,jsonify,request,render_template,Response,flash,redirect,url_for
from flask_restless import APIManager
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_wtf import Form
from wtforms import TextField, BooleanField, validators, PasswordField, SubmitField, SelectField, FileField, \
	SelectMultipleField, BooleanField, DateTimeField
from werkzeug.security import generate_password_hash, \
	 check_password_hash
import datetime
from sqlalchemy import create_engine
#from wtforms.validators import Required
from werkzeug.utils import secure_filename
import os
import uuid

from decimal import *

"""
date for income and expenses = YYYYMMDD so we can accurately compare time

"""


app = Flask(__name__)
# pusher = Pusher(app, url_prefix='/play')
# for now, we will do manual webhooks

DATABASE_PATH = 'sqlite:///database/FinancialAdvisor.db'

UPLOAD_FOLDER = '/static/images'
# only allow images to be uploaded
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'gif'])
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

app = Flask(__name__)
db = SQLAlchemy(app)

app.config.update(dict(
	SECRET_KEY="powerful secretkey",
	WTF_CSRF_SECRET_KEY="a csrf secret key"
))

app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_PATH
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

e = create_engine(DATABASE_PATH)

login_manager = LoginManager()


@login_manager.user_loader
def get_user(ident):
	return User.query.get(int(ident))

class User(db.Model, UserMixin):
	__tablename__ = 'user'
	id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String(32))
	firstname = db.Column(db.String(32))
	lastname = db.Column(db.String(32))
	email = db.Column(db.String(32))
	password = db.Column(db.String(32))

	def __init__(self, username, firstname, lastname, email, password):
		self.username = username
		self.set_password(password)
		self.email = email
		self.firstname = firstname
		self.lastname = lastname

	def set_password(self, password):
		self.password = generate_password_hash(password)

	def check_password(self, password):
		return check_password_hash(self.password, password)
		#return password == self.password


class budget(db.Model):
	__tablename__ = 'budget'
	id = db.Column(db.Integer, primary_key=True)
	user = db.Column(db.Integer, db.ForeignKey("user.id"))
	savings = db.Column(db.Numeric)
	balance = db.Column(db.Numeric)

	userR = db.relationship('User', foreign_keys=[user])

	def __init__(self, user, savings, balance):
		self.user = user
		self.savings = savings
		self.balance = balance


class income(db.Model):
	__tablename__ = 'income'
	id = db.Column(db.Integer, primary_key=True)
	user = db.Column(db.Integer, db.ForeignKey("user.id"))
	date = db.Column(db.Integer)
	amount = db.Column(db.Numeric)

	userR = db.relationship('User', foreign_keys=[user])

	def __init__(self, user, date, amount):
		self.user = user
		self.date = date
		self.amount = amount


class expenses(db.Model):
	__tablename__ = 'expenses'
	id = db.Column(db.Integer, primary_key=True)
	user = db.Column(db.Integer, db.ForeignKey("user.id"))
	date = db.Column(db.Integer)
	amount = db.Column(db.Numeric)
	description = db.Column(db.String(32))

	userR = db.relationship('User', foreign_keys=[user])

	def __init__(self, user, date, amount, description):
		self.user = user
		self.date = date
		self.amount = amount
		self.description = description



class LoginForm(Form):
	username = TextField('Username', [validators.Required()])
	password = PasswordField('Password', [validators.Required()])
	submit = SubmitField('Log In')

	def __init__(self, *args, **kwargs):
		Form.__init__(self, *args, **kwargs)
		self.user = None

	def validate(self):
		user = User.query.filter_by(
			username=self.username.data).first()
		if user is None:
			self.username.errors.append('Unknown username')
			return False

		if not user.check_password(self.password.data):
			self.password.errors.append('Invalid password')
			return False

		self.user = user
		login_user(user)
		return True

class RegisterForm(Form):
	username = TextField('Username', validators=[validators.Required()])
	email = TextField('E-Mail', validators=[validators.Required(), validators.Email()])
	password = PasswordField('Password', [
		validators.Required(),
		validators.EqualTo('confirm', message='Passwords must match')
	])
	confirm = PasswordField('Repeat Password')
	firstname = TextField('First Name', validators=[validators.Required(), validators.Length(min=8, max=32, message="Password must be between 8 and 32 characters long")])
	lastname = TextField('Last Name', validators=[validators.Required()])
	submit = SubmitField('Submit')

	def __init__(self, *args, **kwargs):
		Form.__init__(self, *args, **kwargs)

	def validate(self):
		if self.username.data and self.password.data and self.confirm.data:
			if User.query.filter_by(username=self.username.data).first():
				flash('An account with that username already exists.', category='red')
				return False
			if User.query.filter_by(email=self.email.data).first():
				flash('An account with that email already exists.', category='red')
				return False
			return True
		return False

class IncomeForm(Form):
	date = TextField('Date', validators=[validators.Required()], id="datepicker")
	amount = TextField('Amount', validators=[validators.Required()])
	submit = SubmitField('Submit')

	def __init__(self, *args, **kwargs):
		Form.__init__(self, *args, **kwargs)

	def validate(self):
		if self.date.data and self.amount.data:
			return True
		return False

class ExpensesForm(Form):
	date = TextField('Date', validators=[validators.Required()], id="datepicker")
	amount = TextField('Amount', validators=[validators.Required()])
	description = TextField('Description', validators=[validators.Required()])
	submit = SubmitField('Submit')

	def __init__(self, *args, **kwargs):
		Form.__init__(self, *args, **kwargs)

	def validate(self):
		if self.date.data and self.amount.data and self.description.data:
			return True
		return False

@app.route('/')
def home():
	return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
	form = LoginForm()
	if form.validate_on_submit():
		if form.validate():
			flash("You're now logged in!", category='green')
			return redirect('/dashboard')
		else:
			flash("No user with that email/password combo", category='red')
	return render_template('login.html', form=form)

@app.route("/logout")
@login_required
def logout():
	logout_user()
	return redirect('/')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
	form = RegisterForm()
	if form.validate_on_submit():
		if form.validate():
			user = User(form.username.data, form.firstname.data, form.lastname.data, form.email.data, form.password.data)
			db.session.add(user)
			db.session.commit()
			flash("You're now registered!", category='green')
			return redirect('/login')
		else:
			flash("Error: Check your inputs", category='red')
	return render_template('register.html', form=form)


@app.route('/dashboard')
@login_required
def dashboard():
	user_id = current_user.get_id()
	budget_obj = budget.query.filter_by(user=user_id).first()
	income_list = list(income.query.filter_by(user=user_id).all())

	now = datetime.datetime.now()
	beginning_month = int(now.year * 1e4 + now.month * 1e2 + 1)

	expenses_list = list(expenses.query.filter_by(user=user_id).filter(expenses.date >= beginning_month).all())
	last_three = list(expenses.query.filter_by(user=user_id).order_by(expenses.date.desc()).limit(3).all())

	avg_income = 0
	for i in income_list:
		avg_income += i.amount

	avg_expenses = 0
	for i in expenses_list:
		avg_expenses += i.amount

	# i get paid twice a month, therefore, the average per month is twice the average per paycheck
	avg_income /= len(income_list)
	avg_income *= 2

	return render_template('dashboard.html', budget=budget_obj, income=income_list, avg_income=avg_income, \
		expenses=expenses_list, avg_expenses=avg_expenses, last_three=last_three)

@app.route('/income', methods=['GET', 'POST'])
@login_required
def incomePage():
	form = IncomeForm()
	if form.validate_on_submit():
		if form.validate():
			date_list = form.date.data.split('/')
			date_int = int(date_list[2] + date_list[0] + date_list[1])
			
			i = income(current_user.get_id(), date_int, float(form.amount.data))
			db.session.add(i)
			db.session.commit()

			b = budget.query.filter_by(user=current_user.get_id()).first()
			b.balance += Decimal(form.amount.data)
			db.session.commit()

			flash("New income added!", category='green')
			return redirect('/dashboard')
		else:
			flash("Incorrect information.", category='red')
	return render_template('income.html', form=form)


@app.route('/expense', methods=['GET', 'POST'])
@login_required
def expensePage():
	form = ExpensesForm()
	if form.validate_on_submit():
		if form.validate():
			date_list = form.date.data.split('/')
			date_int = int(date_list[2] + date_list[0] + date_list[1])
			
			e = expenses(current_user.get_id(), date_int, float(form.amount.data), form.description.data)
			db.session.add(e)
			db.session.commit()

			b = budget.query.filter_by(user=current_user.get_id()).first()
			b.balance -= Decimal(form.amount.data)
			db.session.commit()

			flash("New expense added!", category='green')
			return redirect('/dashboard')
		else:
			flash("Incorrect information.", category='red')
	return render_template('expense.html', form=form)

@app.errorhandler(404)
def page_not_found(e):
	return render_template('404.html')


login_manager.init_app(app)

manager = APIManager(app, flask_sqlalchemy_db=db)
manager.create_api(User, methods=['GET'],results_per_page=10)

if __name__ == "__main__":
	app.run(host="0.0.0.0", debug=True)
	#app.run(host='0.0.0.0', port=80)