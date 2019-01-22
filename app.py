from flask_login import LoginManager, login_user, current_user, login_required, logout_user, UserMixin
from flask import Flask,jsonify,request,render_template,Response,flash,redirect,url_for
from flask_restless import APIManager
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_wtf import Form
from wtforms import TextField, BooleanField, validators, PasswordField, SubmitField, SelectField, FileField, \
	SelectMultipleField, BooleanField, DateTimeField, TextAreaField
from werkzeug.security import generate_password_hash, \
	 check_password_hash
import datetime
from sqlalchemy import create_engine
#from wtforms.validators import Required
from werkzeug.utils import secure_filename
import os
import uuid

from flask_mail import Mail, Message

import smtplib
import string

from decimal import *

app = Flask(__name__)

DATABASE_PATH = 'sqlite:///database/Snapdragon.db'

UPLOAD_FOLDER = '/static/images'
# only allow images to be uploaded
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'gif'])
def allowed_file(filename):
	return '.' in filename and \
		   filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

app = Flask(__name__)

# app.config.update(dict(
# 	DEBUG = True,
# 	MAIL_SERVER = 'smtp.gmail.com',
# 	MAIL_PORT = 587,
# 	MAIL_USE_TLS = True,
# 	MAIL_USE_SSL = False,
# 	MAIL_USERNAME = 'asikerd@gmail.com',
# 	MAIL_PASSWORD = 'CheesePuppy',
# ))

db = SQLAlchemy(app)
# mail = Mail(app)

app.config.update(dict(
	SECRET_KEY="powerful secretkey",
	WTF_CSRF_SECRET_KEY="a csrf secret key"
))

app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_PATH
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

e = create_engine(DATABASE_PATH)

login_manager = LoginManager()

COMPANY = {
	'name': 'Snapdragon',
	'motto': 'Coming in clutch'
}


def smtp_gmail(sender_email, subject, message):
	username = "asikerd@gmail.com"
	password = "CheesePuppy"
	smtp_server = "smtp.gmail.com:587"
	email_from = sender_email
	email_to = "asikerd@gmail.com"
	email_body = "From: " + email_from + '\r\n' + "To: " + email_to + '\r\n' + \
	"Subject: " + subject + '\r\n' + message
	
	server = smtplib.SMTP(smtp_server)
	server.starttls()
	server.login(username, password)
	server.sendmail(email_from, email_to, email_body)
	server.quit()



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

class ContactForm(Form):
	email = TextField('Email', [validators.Required()])
	subject = TextField('Subject', [validators.Required()])
	message = TextAreaField('Message', [validators.Required()])
	submit = SubmitField('Log In')

	def __init__(self, *args, **kwargs):
		Form.__init__(self, *args, **kwargs)

	def validate(self):
		return self.email.length and self.subject.length and self.message.length

@app.route('/')
def home():
	images = [
	'https://thumbs-prod.si-cdn.com/rjR9dBkPzbx3tV22Yhi-aA4aCRw=/800x600/filters:no_upscale()/https://public-media.si-cdn.com/filer/a3/3f/a33f8ee0-bfee-4cce-9a13-f9388c5323c0/42-55375529.jpg',
	'https://thenypost.files.wordpress.com/2018/08/180823-florida-super-pythons-feature.jpg?quality=90&strip=all&w=618&h=410&crop=1',
	'http://static.havahart.com/media/articles/images/721/snakes-in-yard.jpg'
	]
	data = []
	sales = []
	for x in range(3):
		i = {'src': images[x]}
		s = {'name': "this item " + str(x), 'description': 'wow what a description'}
		data.append(i)
		sales.append(s)
	return render_template('index.html', featured=data, sales=sales, company=COMPANY)

@app.route('/login', methods=['GET', 'POST'])
def admin_login():
	form = LoginForm()
	if form.validate_on_submit():
		if form.validate():
			flash("You're now logged in!", category='green')
			return redirect('/dashboard')
		else:
			flash("No user with that email/password combo", category='red')
	return render_template('login.html', form=form, company=COMPANY)

@app.route('/admin', methods=['GET', 'POST'])
def login():
	form = LoginForm()
	if form.validate_on_submit():
		if form.validate():
			flash("You're now logged in!", category='green')
			return redirect('/dashboard')
		else:
			flash("No user with that email/password combo", category='red')
	return render_template('login.html', form=form, company=COMPANY)

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
	return render_template('register.html', form=form, company=COMPANY)

@app.route('/contact')
def contact():
	form = ContactForm()
	if form.validate_on_submit():
		if form.validate():
			smtp_gmail(form.email, form.subject, form.message)
			return redirect('/contact')
		else:
			flash("Error", category='red')
	return render_template('contact.html', form=form, company=COMPANY)

@app.route('/about')
def about():
	return render_template('about.html', company=COMPANY)

@app.route('/storefront')
def storefront():
	return render_template('storefront.html', company=COMPANY)

@app.errorhandler(404)
def page_not_found(e):
	return render_template('404.html', company=COMPANY)


login_manager.init_app(app)

manager = APIManager(app, flask_sqlalchemy_db=db)
manager.create_api(User, methods=['GET'],results_per_page=10)

if __name__ == "__main__":
	app.run(host="0.0.0.0", debug=True)
	#app.run(host='0.0.0.0', port=80)