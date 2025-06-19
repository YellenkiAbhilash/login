from flask import Flask, render_template, request, redirect, url_for, flash
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from models import db, User
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')

# Email Configuration
app.config.update(
    MAIL_SERVER=os.getenv('MAIL_SERVER'),
    MAIL_PORT=int(os.getenv('MAIL_PORT')),
    MAIL_USERNAME=os.getenv('MAIL_USERNAME'),
    MAIL_PASSWORD=os.getenv('MAIL_PASSWORD'),
    MAIL_USE_TLS=True,
    MAIL_USE_SSL=False,
    SQLALCHEMY_DATABASE_URI='sqlite:///users.db',
    SQLALCHEMY_TRACK_MODIFICATIONS=False
)

mail = Mail(app)
db.init_app(app)
s = URLSafeTimedSerializer(app.secret_key)

# Create DB
with app.app_context():
    db.create_all()

@app.route('/')
def login():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login_post():
    email = request.form['email']
    password = request.form['password']
    user = User.query.filter_by(email=email).first()
    if user and check_password_hash(user.password, password):
        flash("Logged in successfully!", "success")
    else:
        flash("Invalid credentials", "danger")
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = generate_password_hash(request.form['password'])
        if User.query.filter_by(email=email).first():
            flash("Email already registered", "danger")
        else:
            new_user = User(email=email, password=password)
            db.session.add(new_user)
            db.session.commit()
            flash("Registered successfully!", "success")
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/forgot', methods=['GET', 'POST'])
def forgot():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            token = s.dumps(email, salt='reset-password')
            link = url_for('reset_password', token=token, _external=True)
            msg = Message("Reset Your Password", sender=os.getenv('MAIL_USERNAME'), recipients=[email])
            msg.body = f"Click here to reset your password: {link}"
            mail.send(msg)
            flash("Reset link sent to your email", "info")
        else:
            flash("Email not found", "danger")
    return render_template('forgot_password.html')

@app.route('/reset/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt='reset-password', max_age=600)
    except SignatureExpired:
        return "<h1>Token expired</h1>"

    if request.method == 'POST':
        user = User.query.filter_by(email=email).first()
        new_password = generate_password_hash(request.form['password'])
        user.password = new_password
        db.session.commit()
        flash("Password updated successfully", "success")
        return redirect(url_for('login'))

    return render_template('reset_password.html')
