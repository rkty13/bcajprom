from flask import Flask, render_template, redirect, request
import jinja2
import os
from pymongo import MongoClient
from flask.ext.login import LoginManager, login_user, logout_user, current_user, login_required
from passlib.hash import bcrypt
from bson.objectid import ObjectId, InvalidId
import re
from collections import OrderedDict

app = Flask(__name__)
app.secret_key = os.environ["APP_SECRET"]

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

MONGOLAB_URI = os.environ['MONGOLAB_URI']
client = MongoClient(MONGOLAB_URI)
db = client.get_default_database()
users = db.users
tables = db.tables

EMAIL_REGEX = re.compile("^[a-zA-Z0-9_.+-]+@(?:(?:[a-zA-Z0-9-]+\.)?[a-zA-Z]+\.)?bergen\.org$")

MAX_TABLES = 23
MAX_PEOPLE_PER_TABLE = 8

class User(object):

    def __init__(self, _id):
        self._id = _id
        self.name = users.find_one({ "_id" : ObjectId(_id) })["name"]
    
    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def is_authenticated(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return unicode(self._id)

@login_manager.user_loader
def load_user(_id):
    if id is None:
        redirect("/login")
    user = User(_id)
    if user.is_active():
        return user
    return None

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated() and current_user.is_active():
        return redirect("/")
    if request.method == "POST":
        email = request.form["email"].lower()
        if not EMAIL_REGEX.match(email):
            return render_template("login.html", error="Please enter a valid email")
        password = request.form["password"]
        if userAuth(email, password):
            user = users.find_one({ "email" : re.compile(email, re.IGNORECASE) })
            login_user(User(unicode(user["_id"])))
            return redirect("/")
        else:
            return render_template("login.html", error="Wrong email or password")
    return render_template("login.html")

def userAuth(email, password):
    user = users.find_one({ "email" : re.compile(email, re.IGNORECASE) })
    if (user == None):
        return False
    return bcrypt.verify(password, user["password"])

@app.route("/logout", methods=["GET", "POST"])
def logout():
    logout_user()
    return redirect("/login")

@app.route("/create_account", methods=["GET", "POST"])
def create():
    if request.method == "POST":
        user = {}
        user["name"] = str(request.form["name"])
        if not EMAIL_REGEX.match(request.form["email"].lower()):
            return render_template(
                "create_account.html", 
                message="Please enter a valid Email address"
            )
        user["email"] = request.form["email"].lower()
        user["password"] = hashPassword(request.form["password"])
        if users.find_one({ "email" : user["email"] }) != None:
            return render_template("create_account.html", message="Already Exists")
        users.insert(user)
        return render_template("create_account.html", message="User Created")
    return render_template("create_account.html")

def hashPassword(password):
    return bcrypt.encrypt(password)

@app.route("/tables", methods=["GET", "POST"])
def list_tables():
    status = None
    if request.method == "POST":
        if request.form["status"] == "leave":
            status = removeUserTable(current_user.name, ObjectId(request.form["id"]))
        elif request.form["status"] == "join":
            status = addUserTable(current_user.name, ObjectId(request.form["id"]))
    results = []
    dbresults = tables.find()
    for result in dbresults:
        results.append(result)
    results = sorted(results)
    cur_table_num = -1
    if current_user.is_authenticated():
        name = current_user.name.lower()
        for table in results:
            for user in table["people"]:
                if user.lower() == name:
                    cur_table_num = table["number"]
    return render_template("tables.html", 
        is_authed=current_user.is_authenticated(),
        results=results, 
        table_num=cur_table_num, 
        status=status, 
        max_people=MAX_PEOPLE_PER_TABLE
    )

@app.route("/create_table", methods=["GET", "POST"])
def table():
    if request.method == "POST":
        total_tables = tables.find().count()
        if total_tables == MAX_TABLES:
            return render_template("create_table.html", message="Too Many Tables")
        new_table = {}
        new_table["number"] = total_tables + 1
        new_table["people"] = []
        tables.insert(new_table)
        table = tables.find_one({ "number" : total_tables + 1 })
        return render_template("create_table.html", message="Table " + str(total_tables + 1) + " Created")
    return render_template("create_table.html")

# user: String with user name
# table_id: id of table in tables collection
def addUserTable(name, table_id):
    table = tables.find_one({ "_id" : table_id })
    if table == None:
        return False
    user_list = table["people"]
    if name in user_list or len(user_list) == MAX_PEOPLE_PER_TABLE:
        return False
    tables.update(
        { "_id" : table_id }, 
        { "$push" : { "people" : name } },
        upsert=False
    )
    return True

def removeUserTable(name, table_id):
    table = tables.find_one({ "_id" : table_id })
    if table == None:
        return False
    user_list = table["people"]
    if not name in user_list:
        return False
    tables.update(
        { "_id" : table_id },
        { "$pull" : { "people" : name } },
        upsert=False
    )
    return True

@app.route("/")
def index():
    return render_template("index.html")

if __name__ == "__main__":
    debug = True
    if "DYNO" in os.environ:
        debug = False
    port = int(os.environ.get("PORT", 8000))
    app.run(host="0.0.0.0", port=port,debug=debug)

