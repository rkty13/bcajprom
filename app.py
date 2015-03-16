from flask import Flask, render_template, redirect, request
import jinja2
import os
from pymongo import MongoClient
from flask.ext.login import LoginManager, login_user, logout_user, current_user, login_required
from passlib.hash import bcrypt
from bson.objectid import ObjectId, InvalidId

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

MAX_TABLES = 10
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
        email = request.form["email"]
        password = request.form["password"]
        if (userAuth(email, password)):
            user = users.find_one({"email" : email})
            login_user(User(unicode(user["_id"])))
            return redirect("/")
        else:
            return render_template("login.html", error="Wrong email or password")
    return render_template("login.html")

def userAuth(email, password):
    user = users.find_one({"email" : email})
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
        user["email"] = str(request.form["email"])
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
    results = {}
    results = tables.find()
    results = list(results)
    name = current_user.name.lower()
    table_num = -1
    for table in results:
        for user in table["people"]:
            if user.lower() == name.lower():
                table_num = table["number"]
    return render_template("tables.html", results=results, table_num=table_num)

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
        lst = addUserTable(current_user.name, table["_id"])
        return render_template("create_table.html", message="Table Created", lst=lst)
    return render_template("create_table.html")

# user: String with user name
# table_id: id of table in tables collection
def addUserTable(name, table_id):
    table = tables.find_one({ "_id" : table_id })
    if table == None:
        return False
    user_list = table["people"]
    if name in user_list:
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

