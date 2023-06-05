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

def l1_required(func):
    @wraps(func)
    def decorated_view(*args, **kwargs):
        if session.get('role') == 'admin' or session.get('role') == 'L1':
            return func(*args, **kwargs)
        abort(403)
    return decorated_view


def l2_required(func):
    @wraps(func)
    def decorated_view(*args, **kwargs):
        if session.get('role') == 'admin' or session.get('role') == 'L2':
            return func(*args, **kwargs)
        abort(403)
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
@login_required
def Defination():
    return redirect("/dashboard")
    

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
    if role != "admin":
        return redirect(f"/dashboard/{role}")

    users_count = db.session.query(User).count()
    total_log_count = db.session.query(Log).count()
    total_ticket_count = db.session.query(Log).filter(
        Log.ticketCreated == True).count()

    return render_template('dashboard.html', role=role, users_count=users_count, total_log_count=total_log_count, total_ticket_count=total_ticket_count)


# ------------ Log Management ------------ #

class Log(db.Model):
    __tablename__ = 'Log'
    id = db.Column(db.Integer, primary_key=True)
    command = db.Column(db.String,  nullable=False)
    ip_port = db.Column(db.String, nullable=False)
    timestand = db.Column(db.DateTime, nullable=False)
    level = db.Column(db.Integer, nullable=False)
    source = db.Column(db.String, nullable=False)
    deleted = db.Column(db.Boolean, nullable=False)
    escalated = db.Column(db.Boolean, nullable=False)
    ticketCreated = db.Column(db.Boolean, nullable=False)
    description = db.Column(db.String, nullable=True)


@app.route("/dashboard/<string:role>", methods=['GET'])
@login_required
def log_dashboard(role):
    if role == "L1" and (session.get('role') == 'L1' or session.get('role') == 'admin'):
        logs = db.session.query(Log).filter(
        Log.escalated == False).filter(Log.deleted == False).order_by(Log.timestand.desc())
        return render_template('log/logs.html', logs=logs)

    elif role == "L2" and (session.get('role') == 'L2' or session.get('role') == 'admin'):
        logs = db.session.query(Log).filter(
            Log.escalated == True).filter(Log.deleted == False).filter(Log.escalated==True).filter(Log.ticketCreated==False).order_by(Log.timestand.desc())
        return render_template('log/logs.html', logs=logs)
        
    elif role == "admin" and session.get('role') == 'admin':
        logs = db.session.query(Log).order_by(Log.timestand.desc())
        return render_template('log/logs.html', logs=logs)

    else:
        abort(403)


@app.route("/log/<int:id>/delete", methods=["POST"])
@login_required
def log_delete(id):
    try:
        referrer_path = request.referrer.split("?")[0]
    except:
        referrer_path = request.referrer

    log = db.get_or_404(Log, id)
    log.deleted = True
    db.session.commit()

    if session.get('role') == 'admin' and "/tickets" in referrer_path:
        db.session.delete(log)
        db.session.commit()
        return redirect(f"/tickets?delete=true")
    
    return redirect(f"{referrer_path}?delete=true")


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
        deleted=False,
        escalated=False,
        ticketCreated=False
    )

    db.session.add(log)
    db.session.commit()

    return "OK"


@app.route("/log/<int:id>/escale", methods=["POST"])
@l1_required
@login_required
def log_escale(id):
    log = db.get_or_404(Log, id)
    log.escalated = True
    db.session.commit()
    return redirect("/dashboard/L1?escale=true")


@app.route("/log/<int:id>/unescale", methods=["POST"])
@l2_required
@login_required
def log_unescale(id):
    log = db.get_or_404(Log, id)
    log.escalated = False
    db.session.commit()
    return redirect("/dashboard/L2?unescale=true")


@app.route("/log/<int:id>/create_ticket", methods=["GET","POST"])
@l2_required
@login_required
def create_ticket(id):
    if request.method == "GET":
        log = db.get_or_404(Log, id)
        return render_template('log/create_ticket.html', log=log)
    
    if request.method == "POST":
        log = db.get_or_404(Log, id)
        log.ticketCreated = True
        log.level = int(request.form["level"])
        log.description = request.form["desc"]
        db.session.commit()
        return redirect("/dashboard/L2?create_ticket=true")

@app.route("/log/<int:id>/get_ticket", methods=["POST"])
@admin_required
@login_required
def get_ticket(id):
    log = db.get_or_404(Log, id)

    return redirect("/dashboard/L2?create_ticket=true")

@app.route("/tickets", methods=["GET","POST"])
@admin_required
@login_required
def ticket_list():
    logs = db.session.query(Log).filter(Log.ticketCreated == True).order_by(Log.timestand.desc())
    return render_template('log/ticket_list.html', logs=logs)


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


@app.route("/user/<int:id>/change_role/<string:direction>", methods=["POST"])
@admin_required
def change_role(id, direction):
    user = db.get_or_404(User, id)
    if direction == "up":
        if user.role == "L1":
            user.role = "L2"
        elif user.role == "L2":
            user.role = "admin"

    if direction == "down":
        if user.role == "admin":
            user.role = "L2"
        elif user.role == "L2":
            user.role = "L1"
    
    db.session.commit()
    return redirect("/users?changerole=true")


@app.route("/users", methods=['GET'])
@admin_required
def users():
    users = db.session.execute(db.select(User).order_by(User.id.desc())).scalars()
    return render_template('user/list.html', users=users)
