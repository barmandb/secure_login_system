from flask import Flask, render_template, request, redirect, url_for, flash
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
import sqlite3
import random

app = Flask(__name__)
app.secret_key = "change_this_to_a_long_random_secret_key"

bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "home"

# Mail config
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = "your_email@gmail.com"
app.config["MAIL_PASSWORD"] = "your_app_password"

mail = Mail(app)
serializer = URLSafeTimedSerializer(app.secret_key)

otp_store = {}

def connect_db():
    conn = sqlite3.connect("database.db")
    conn.row_factory = sqlite3.Row
    return conn

class User(UserMixin):
    def __init__(self, user_id, username):
        self.id = str(user_id)
        self.username = username

@login_manager.user_loader
def load_user(user_id):
    db = connect_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    db.close()
    if user:
        return User(user["id"], user["username"])
    return None

def send_otp(email):
    otp = str(random.randint(100000, 999999))
    otp_store[email] = otp

    msg = Message(
        "Your OTP Code",
        sender=app.config["MAIL_USERNAME"],
        recipients=[email]
    )
    msg.body = f"Your OTP is: {otp}"
    mail.send(msg)

@app.route("/")
def home():
    return render_template("login.html")

@app.route('/register', methods=['POST'])
def register():
    username = request.form['username'].strip()
    password = request.form['password']

    hashed = bcrypt.generate_password_hash(password).decode('utf-8')

    db = connect_db()
    try:
        db.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed))
        db.commit()
        flash("Registered successfully! Please login.", "success")
    except sqlite3.IntegrityError:
        flash("This email is already registered.", "error")

    db.close()
    return redirect(url_for('home'))

@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"].strip()
    password = request.form["password"]

    db = connect_db()
    user = db.execute(
        "SELECT * FROM users WHERE username = ?",
        (username,)
    ).fetchone()
    db.close()

    if not user:
        flash("No account found with this email.", "error")
        return redirect(url_for("home"))

    if not bcrypt.check_password_hash(user["password"], password):
        flash("Incorrect password.", "error")
        return redirect(url_for("home"))

    try:
        send_otp(username)
    except Exception as e:
        flash(f"Login correct, but OTP email failed: {str(e)}", "error")
        return redirect(url_for("home"))

    return render_template("otp.html", email=username)

@app.route("/verify_otp", methods=["POST"])
def verify_otp():
    email = request.form["email"].strip()
    otp = request.form["otp"].strip()

    if otp_store.get(email) == otp:
        db = connect_db()
        user = db.execute(
            "SELECT * FROM users WHERE username = ?",
            (email,)
        ).fetchone()
        db.close()

        if user:
            user_obj = User(user["id"], user["username"])
            login_user(user_obj)
            otp_store.pop(email, None)
            return redirect(url_for("dashboard"))

    flash("Invalid OTP.", "error")
    return render_template("otp.html", email=email)

@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out successfully.", "success")
    return redirect(url_for("home"))

@app.route("/reset_request", methods=["POST"])
def reset_request():
    email = request.form["email"].strip()
    if not email:
        flash("Enter your email to reset password.", "error")
        return redirect(url_for("home"))

    token = serializer.dumps(email, salt="reset-password")
    link = url_for("reset_password", token=token, _external=True)

    try:
        msg = Message(
            "Password Reset Request",
            sender=app.config["MAIL_USERNAME"],
            recipients=[email]
        )
        msg.body = f"Click this link to reset your password:\n\n{link}\n\nThis link expires in 5 minutes."
        mail.send(msg)
        flash("Password reset link sent to your email.", "success")
    except Exception as e:
        flash(f"Reset email failed: {str(e)}", "error")

    return redirect(url_for("home"))

@app.route("/reset/<token>", methods=["GET", "POST"])
def reset_password(token):
    try:
        email = serializer.loads(token, salt="reset-password", max_age=300)
    except Exception:
        return "Reset link is invalid or expired."

    if request.method == "POST":
        new_password = request.form["password"]
        if not new_password:
            return "Password cannot be empty."

        hashed_password = bcrypt.generate_password_hash(new_password).decode("utf-8")

        db = connect_db()
        db.execute(
            "UPDATE users SET password = ? WHERE username = ?",
            (hashed_password, email)
        )
        db.commit()
        db.close()

        flash("Password updated successfully. Please login.", "success")
        return redirect(url_for("home"))

    return render_template("reset.html", email=email)

if __name__ == "__main__":
    app.run(debug=True)