from flask import Flask, render_template, request, redirect, session, abort, url_for
import sqlite3
from hashlib import sha256
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from datetime import datetime


db = SQLAlchemy()
app = Flask(__name__)
app.secret_key = "7sgedXGd5Uym7d"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///project.db"
db.init_app(app)


# --------------- Decorators --------------- #

def admin_required(func):
    @wraps(func)
    def decorated_view(*args, **kwargs):
        if session.get('role') != 'admin':
            abort(403)
        return func(*args, **kwargs)
    return decorated_view


def login_required(func):
    @wraps(func)
    def decorated_view(*args, **kwargs):
        if 'username' not in session:
            return redirect("/login")
        return func(*args, **kwargs)
    return decorated_view


# --------------- Base Views --------------- #


@app.route("/")
def Defination():
    if 'username' in session:
        return redirect("/dashboard")
    return redirect("/login")


@app.route("/login", methods=['GET'])
def Login():
    if 'username' in session:
        return redirect("/dashboard")

    error = request.args.get("error")
    logout = request.args.get("logout")
    if error:
        return render_template('account/login.html', error=True, logout=False)
    elif logout:
        return render_template('account/login.html', error=False, logout=True)
    else:
        return render_template('account/login.html', error=False, logout=False)


@app.route("/dashboard", methods=['GET'])
@login_required
def dashboard():
    role = session['role']
    users_count = db.session.query(User).count()
    total_log_count = db.session.query(Log).count()
    current_log_count = db.session.query(Log).filter(
        Log.user_viewable == True).count()

    return render_template('dashboard.html', role=role, users_count=users_count, total_log_count=total_log_count, current_log_count=current_log_count)


# ------------ Log Management ------------ #

class Log(db.Model):
    __tablename__ = 'Log'
    id = db.Column(db.Integer, primary_key=True)
    command = db.Column(db.String,  nullable=False)
    ip_port = db.Column(db.String, nullable=False)
    timestand = db.Column(db.DateTime, nullable=False)
    level = db.Column(db.Integer, nullable=False)
    source = db.Column(db.String, nullable=False)
    user_viewable = db.Column(db.Boolean, nullable=False)


@app.route("/log/dashboard", methods=['GET'])
@login_required
def log_dashboard():
    logs = db.session.query(Log).filter(
        Log.user_viewable == True).order_by(Log.timestand)
    return render_template('log/dashboard.html', logs=logs)


@app.route("/log/history", methods=['GET'])
@admin_required
def log_history():
    logs = db.session.query(Log).order_by(Log.timestand)
    return render_template('log/history.html', logs=logs)


@app.route("/log/<int:id>/delete", methods=["POST"])
@admin_required
def log_delete(id):
    log = db.get_or_404(Log, id)
    db.session.delete(log)
    db.session.commit()
    return redirect("/log/history?delete=true")


@app.route("/log/create", methods=["POST"])
def log_create():
    data = request.json
    timestamp_str = data.get('timestand')
    timestamp_obj = datetime.strptime(timestamp_str, '%d/%b/%Y %H:%M:%S')

    log = Log(
        command=data.get('command'),
        ip_port=data.get('ip_port'),
        timestand=timestamp_obj,
        level=data.get('level'),
        source=data.get('source'),
        user_viewable=True
    )

    db.session.add(log)
    db.session.commit()

    return "OK"


@app.route("/log/<int:id>/escale", methods=["POST"])
@login_required
def log_escale(id):
    log = db.get_or_404(Log, id)

    if log.user_viewable == True:
        log.user_viewable = False
    elif log.user_viewable == False and session['role'] == 'admin':
        log.user_viewable = True
    else:
        abort(403)

    db.session.commit()
    if "dashboard" in request.referrer:
        return redirect("/log/dashboard?escale=true")
    elif "history" in request.referrer:
        return redirect("/log/history?unescale=true")

# --------- Session Management --------- #


@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login?logout=true')


@app.route('/settings')
@login_required
def settings():
    return render_template('account/settings.html', success=request.args.get("success"))


@app.route("/submit", methods=['POST'])
def Submit():

    username = request.form['username']
    password = sha256(request.form['password'].encode()).hexdigest()

    user = db.session.query(User).filter(
        User.username == username).order_by(User.username).first()

    if user and user.password == password:
        session['id'] = user.id
        session['username'] = user.username
        session['role'] = user.role
        return redirect("/dashboard")
    else:
        return redirect("/login?error=true")


# ------------------ User ------------------ #

class User(db.Model):
    __tablename__ = 'User'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True, nullable=False)
    password = db.Column(db.String, nullable=False)
    role = db.Column(db.String, nullable=False)


@app.route("/user/create", methods=["POST"])
@admin_required
def user_create():
    user = User(
        username=request.form["username"],
        password=sha256(request.form["password"].encode()).hexdigest(),
        role=request.form["role"],
    )

    db.session.add(user)
    db.session.commit()
    return redirect('/users?create=true')


@app.route("/user/<int:id>/delete", methods=["POST"])
@admin_required
def user_delete(id):
    user = db.get_or_404(User, id)
    db.session.delete(user)
    db.session.commit()
    return redirect("/users?delete=true")


@app.route("/user/change_password", methods=["POST"])
@login_required
def change_password():
    user = db.get_or_404(User, session['id'])

    if sha256(request.form["current-password"].encode()).hexdigest() != user.password:
        return redirect("/settings?success=false")

    if not (request.form["new-password"] == request.form["confirm-password"]):
        return redirect("/settings?success=false")

    user.password = sha256(
        request.form["confirm-password"].encode()).hexdigest()

    db.session.commit()
    return redirect("/settings?success=true")


@app.route("/user/<int:id>/change_role", methods=["POST"])
@admin_required
def change_role(id):
    user = db.get_or_404(User, id)
    user.role = "admin" if user.role == "user" else "user"
    db.session.commit()
    return redirect("/users?changerole=true")


@app.route("/users", methods=['GET'])
@admin_required
def users():
    users = db.session.execute(db.select(User).order_by(User.role)).scalars()
    return render_template('user/list.html', users=users)
