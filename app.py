from flask import Flask,request,session,redirect,flash,render_template
import os
from dotenv import load_dotenv
import auth
import db
from functools import wraps

load_dotenv("password.env")

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")

@app.context_processor
def inject_user():
    if "user_id" in session:
        u = db.fetch_user_by_id(session["user_id"])
        if u:
            return {"current_user_name": u.get("username"),
                    "current_user_role": u.get("role")}
    return {"current_user_name": None, "current_user_role": None}


# ---------------- decorators ----------------
def login_required(f):
    @wraps(f)
    def wrapper(*args,**kwargs):
        if "user_id" not in session:
            return redirect("/login")
        if not db.is_session_active(session.get("session_id")):
            session.clear()
            return redirect("/login")
        return f(*args,**kwargs)
    return wrapper

def roles_required(*allowed_roles):
    def decorator(f):
        @wraps(f)
        def wrapper(*args,**kwargs):
            if "user_id" not in session:
                return redirect("/login")
            if not db.is_session_active(session.get("session_id")):
                session.clear()
                return redirect("/login")
            user = db.fetch_user_by_id(session["user_id"])
            if not user or user["role"] not in allowed_roles:
                flash("Not authorized")
                return redirect("/dashboard")
            return f(*args,**kwargs)
        return wrapper
    return decorator


# ---------------- auth ----------------
@app.route("/login",methods=["GET","POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")
    username = request.form["username"]
    password = request.form["password"]
    if username and password:
        user = db.fetch_user(username)
        if user:
            if not auth.verify_password(password,user["password"]):
                return redirect("/login")
            session["user_id"] = user["id"]
            session["session_id"] = db.save_login_session(session["user_id"],request.remote_addr)
            db.log_action(user["id"],"login","active_sessions",session["session_id"],"user logged in")
            return redirect("/dashboard")
        flash("Incorrect credentials,Try Again!")
        return redirect("/login")
    flash("username and password cannot be empty")
    return redirect("/login")

@app.route("/logout",methods=["POST"])
def logout():
    db.log_action(session["user_id"],"logout","active_sessions",session["session_id"],"user logged out")
    db.logout_session(session["session_id"])
    session.clear()
    return redirect("/login")


# ---------------- dashboard ----------------
@app.route("/dashboard",methods=["GET"])
@login_required
def dashboard():
    user = db.fetch_user_by_id(session["user_id"])
    counts = db.severity_count()
    recent = db.get_recent_incidents()
    logins = db.dashboard_logins()
    return render_template("dashboard.html",user=user,counts=counts,recent=recent,logins=logins)


# ---------------- incidents ----------------
@app.route("/incidents",methods=["GET"])
@login_required
def incidents():
    status = request.args.get("status")
    source = request.args.get("source")
    severity = request.args.get("severity")
    incidents = db.fetch_incidents(status,source,severity)
    return render_template("incidents.html",incidents=incidents)

@app.route("/incidents/<int:incident_id>",methods=["GET","POST"])
@login_required
def incident_detail(incident_id):
    if request.method == "POST":
        content = request.form["content"]
        if content:
            db.add_note(incident_id,session["user_id"],content)
            db.log_action(session["user_id"],"add_note","incidents",incident_id,"note added")
        return redirect(f"/incidents/{incident_id}")
    incident = db.fetch_incident_by_id(incident_id)
    if not incident:
        flash("Incident not found")
        return redirect("/incidents")
    notes = db.fetch_notes_by_id(incident_id)
    return render_template("incident_detail.html",incident=incident,notes=notes)

@app.route("/incidents/<int:incident_id>/status",methods=["POST"])
@roles_required("analyst","manager","admin")
def change_status(incident_id):
    status = request.form["status"]
    db.update_status(incident_id,status)
    db.log_action(session["user_id"],"status_change","incidents",incident_id,f"status changed to {status}")
    return redirect(f"/incidents/{incident_id}")

@app.route("/incidents/<int:incident_id>/assign",methods=["POST"])
@roles_required("manager","admin")
def assign(incident_id):
    assigned_to = request.form["assigned_to"]
    db.assign_incident(incident_id,assigned_to)
    db.log_action(session["user_id"],"assign","incidents",incident_id,f"assigned to user {assigned_to}")
    return redirect(f"/incidents/{incident_id}")


# ---------------- users (admin) ----------------
@app.route("/users")
@roles_required("admin")
def users():
    all_users = db.fetch_all_users()
    return render_template("users.html",users=all_users)

@app.route("/users/<int:user_id>/role",methods=["POST"])
@roles_required("admin")
def change_user_role(user_id):
    role = request.form["role"]
    db.change_role(role,user_id)
    db.log_action(session["user_id"],"role_change","users",user_id,f"role changed to {role}")
    return redirect("/users")

@app.route("/users/<int:user_id>/delete",methods=["POST"])
@roles_required("admin")
def remove_user(user_id):
    if user_id == session["user_id"]:
        flash("You can't delete your own account")
        return redirect("/users")
    db.delete_user(user_id)
    db.log_action(session["user_id"],"delete_user","users",user_id,"user deleted")
    return redirect("/users")


# ---------------- sessions (manager/admin) ----------------
@app.route("/sessions")
@roles_required("manager","admin")
def sessions():
    active = db.fetch_active_sessions()
    return render_template("sessions.html",sessions=active)

@app.route("/sessions/<int:session_id>/logout",methods=["POST"])
@roles_required("manager","admin")
def force_logout(session_id):
    db.logout_session(session_id)
    db.log_action(session["user_id"],"force_logout","active_sessions",session_id,"session force-logged-out")
    return redirect("/sessions")


# ---------------- audit (admin/auditor) ----------------
@app.route("/audit")
@roles_required("admin","auditor")
def audit():
    entries = db.fetch_audit_log()
    return render_template("audit.html",entries=entries)


if __name__ == '__main__':
    app.run(host='0.0.0.0',port=5000,debug=True,threaded=True)
