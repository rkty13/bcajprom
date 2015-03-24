from flask import Flask, render_template, redirect, request, abort
import jinja2
import os
from pymongo import MongoClient
from flask.ext.login import LoginManager, login_user, logout_user, current_user, login_required
from passlib.hash import bcrypt
from bson.objectid import ObjectId, InvalidId
import re
import sendgrid
from sendgrid import SendGridError, SendGridClientError, SendGridServerError

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

SENDGRID_API_USER = os.environ["SENDGRID_API_USER"]
SENDGRID_API_KEY = os.environ["SENDGRID_API_KEY"]
sg = sendgrid.SendGridClient(SENDGRID_API_USER, SENDGRID_API_KEY)

MAX_TABLES = 23
MAX_PEOPLE_PER_TABLE = 12

class User(object):

    def __init__(self, _id):
        self._id = _id
        user = users.find_one({ "_id" : ObjectId(_id) })
        self.first_name = user["first_name"]
        self.last_name = user["last_name"]
        self.email = user["email"]
    
    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def is_authenticated(self):
        return True

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
            return render_template("login.html", 
                error="Please enter a valid email")
        password = request.form["password"]
        user = users.find_one({ "email" : re.compile(email, re.IGNORECASE) })
        if userAuth(user, email, password):
            if not user["confirmed"]:
                return render_template(
                    "login.html",
                    error="Please accept the confirmation email.")
            login_user(User(unicode(user["_id"])))
            return redirect("/")
        else:
            return render_template(
                "login.html", 
                error="Wrong email or password")
    return render_template("login.html")

def userAuth(user, email, password):
    if (user == None):
        return False
    return bcrypt.verify(password, user["password"])

@app.route("/logout", methods=["GET", "POST"])
def logout():
    logout_user()
    return redirect("/")

@app.route("/create_account", methods=["GET", "POST"])
def create():
    if request.method == "POST":
        user = {}

        if not (request.form["first_name"] and 
                request.form["last_name"] and
                request.form["email"] and 
                request.form["password"] and 
                request.form["verify_password"]):
            return render_template(
                "create_account.html",
                error="Please fill out all fields")
        user["first_name"] = request.form["first_name"]
        user["last_name"] = request.form["last_name"]

        if not EMAIL_REGEX.match(request.form["email"].lower()):
            return render_template(
                "create_account.html", 
                error="Please enter a valid email address")

        if users.find_one({ "email" : re.compile(request.form["email"], re.IGNORECASE) }) != None:
            return render_template(
                "create_account.html", 
                error="Account with email already exists")
        user["email"] = request.form["email"].lower()
        
        if not request.form["password"] == request.form["verify_password"]:
            return render_template(
                "create_account.html", 
                error="Password verification failed")

        user["password"] = hashPassword(request.form["password"])
        user["confirmed"] = False
        users.insert(user)
        email_user = users.find_one({ "email" : re.compile(request.form["email"], re.IGNORECASE) })
        email(email_user["email"], 
            "RobKim@bergen.org",
            "BCA JProm Website Registration",
            email_user["first_name"],
            str(email_user["_id"]))
        return render_template(
            "create_account.html", 
            success="User Created!")
    
    return render_template("create_account.html")

def email(toEmail, fromEmail, subject, first_name, id):
    try:    
        message = sendgrid.Mail(
            to=toEmail,
            subject=subject,
            html= ("<html><body>" + 
                    "<p>Hey " + first_name + ",</p>" +
                    "<p>Thanks for signing up for the BCA JProm site! " + 
                    "Confirm your account <a href='http://bcajprom.herokuapp.com/confirm/" + id + "'>here</a>.</p>" + 
                    "<p>Thanks,</p>" +
                    "<p>Robert Kim</p>" + 
                    "<p>If you did not create this account, please contact me at RobKim@bergen.org.</p>" +
                    "</body></html>"),
            from_email=fromEmail)
        status, msg = sg.send(message)
    except SendGridClientError: 
        return render_template(
            "create_account.html", 
            error="Error from client sending confirmation email.")
    except SendGridServerError:
        return render_template(
            "create_account.html", 
            error="Error from server sending confirmation email.")

def hashPassword(password):
    return bcrypt.encrypt(password)

@app.route("/tables", methods=["GET", "POST"])
def list_tables():
    status = None
    if request.method == "POST":
        ff = ObjectId(current_user.get_id())
        person = users.find_one({ "_id" : ObjectId(current_user.get_id()) })
        if request.form["status"] == "leave":
            status = removeUserTable(
                person,
                ObjectId(request.form["id"]))
        elif request.form["status"] == "join":
            status = addUserTable(
                person,
                ObjectId(request.form["id"]))
    results = []
    dbresults = tables.find()
    
    for result in dbresults:
        results.append(result)
    results = sorted(results)
    cur_table_num = -1
    
    if current_user.is_authenticated():
        name = current_user.first_name.lower() + " " + current_user.last_name.lower()
        for table in results:
            for user in table["people"]:
                if user["name"].lower() == name:
                    cur_table_num = table["number"]
    
    return render_template(
        "tables.html", 
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
            return render_template(
                "create_table.html", 
                message="Too Many Tables")
        
        new_table = {}
        new_table["number"] = total_tables + 1
        new_table["people"] = []
        tables.insert(new_table)
        table = tables.find_one({ "number" : total_tables + 1 })
        return render_template(
            "create_table.html", 
            message="Table " + 
                str(total_tables + 
                    1) + " Created")
    
    return render_template("create_table.html")

# user: String with user name
# table_id: id of table in tables collection
def addUserTable(person, table_id):
    table = tables.find_one({ "_id" : table_id })
    name = person["first_name"] + " " + person["last_name"]
    if table == None:
        return False
    user_list = table["people"]
    if len(user_list) == MAX_PEOPLE_PER_TABLE:
        return False

    for user in user_list:
        if person["email"].lower() == user["email"].lower():
            return False

    tables.update(
        { "_id" : table_id }, 
        { "$push" : { "people" : { "name" : name, "email" : person["email"] } } },
        upsert=False
    )
    return True

def removeUserTable(person, table_id):
    table = tables.find_one({ "_id" : table_id })
    name = person["first_name"] + " " + person["last_name"]
    if table == None:
        return False
    user_list = table["people"]
    in_list = False
    for user in user_list:
        if person["email"].lower() == user["email"].lower():
            in_list = True
    if not in_list:
        return in_list
    tables.update(
        { "_id" : table_id },
        { "$pull" : { "people" : { "name" : name, "email" : person["email"] } } },
        upsert=False
    )
    return True

@app.route("/confirm/<id>")
def confirm(id):
    try:
        oid = ObjectId(id)
        person = users.find_one({ "_id" : oid })
        if person == None:
            abort(404)
        users.update(
            { "_id" : oid },
            { "$set" : { "confirmed" : True } },
            upsert=False)
        redirect("/login")
    except InvalidId as error:
        abort(404)
    except:
        abort(404)
    return render_template("confirm.html")

@app.route("/")
def index():
    return render_template("index.html")

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

if __name__ == "__main__":
    debug = True
    if "DYNO" in os.environ:
        debug = False
    port = int(os.environ.get("PORT", 8000))
    app.run(host="0.0.0.0", port=port,debug=debug)

