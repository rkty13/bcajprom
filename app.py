from flask import Flask, render_template, redirect, request
import jinja2
import os
from pymongo import MongoClient
from flask.ext.login import LoginManager, login_user, logout_user, current_user, login_required
import hashlib, uuid


app = Flask(__name__)
app.secret_key = os.environ["APP_SECRET"]

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

class User(object):
	def __init__(self, userid, username, password, active=True):
		self.userid = userid
		self.username = username
		self.password = password

	def is_active(self):
		return True

	def is_anonymous(self):
		return False

	def is_authenticated(self):
		return True

	def is_anonymous(self):
		return False

	def get_id(self):
		return self.userid

@login_manager.user_loader
def load_user(userid):
	return User(userid, "rkty13", "asdf")

@app.route("/login", methods=["GET", "POST"])
def login():
	if current_user.is_authenticated() and current_user.is_active():
		return redirect("/")
	if request.method == "POST":
		email = request.form["email"]
		password = request.form["password"]
		if (checkUser(email, password)):
			#login_user(User(email, password))
			return redirect("/")
		else:
			return render_template("login.html", error="Wrong email or password")
	return render_template("login.html")

def checkUser(email, password):
	
	return True

@app.route("/")
def index():
	return render_template("index.html")

if __name__ == "__main__":
	debug = True
	if "DYNO" in os.environ:
	    debug = False
	port = int(os.environ.get("PORT", 8000))
	app.run(host="0.0.0.0", port=8000,debug=debug)

