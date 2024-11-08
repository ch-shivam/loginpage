from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from twilio.rest import Client
from werkzeug.security import generate_password_hash, check_password_hash
import random
import os
import time

app = Flask(__name__)
app.secret_key = os.urandom(24)

# SQLite Database Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Twilio configuration (Replace with your credentials)
account_sid = 'your_twilio_account_sid'
auth_token = 'your_twilio_auth_token'
twilio_phone_number = 'your_twilio_phone_number'
client = Client(account_sid, auth_token)

# In-memory attempt tracker
attempts_db = {}

# User Model for SQLite Database
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    phone_number = db.Column(db.String(15), nullable=False)
    otp = db.Column(db.Integer, nullable=True)
    otp_timestamp = db.Column(db.Integer, nullable=True)

# Create the tables if they do not exist
with app.app_context():
    db.create_all()

# Function to send OTP via SMS
def send_otp(phone_number, otp):
    message = client.messages.create(
        body=f"Your OTP is: {otp}",
        from_=twilio_phone_number,
        to=phone_number
    )
    return message.sid

# Registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        phone_number = request.form['phone_number']

        # Check if the username already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash("Username already exists!", "danger")
            return redirect(url_for('register'))

        # Hash the password before storing
        password_hash = generate_password_hash(password)

        # Generate and send OTP
        otp = random.randint(100000, 999999)
        send_otp(phone_number, otp)

        # Store user details temporarily in the database
        new_user = User(username=username, password_hash=password_hash, phone_number=phone_number, otp=otp, otp_timestamp=int(time.time()))
        db.session.add(new_user)
        db.session.commit()

        # Redirect to OTP verification page
        return redirect(url_for('otp_verification', username=username))

    return render_template('register.html')

# OTP verification route
@app.route('/otp_verification', methods=['GET', 'POST'])
def otp_verification():
    username = request.args.get('username')
    user = User.query.filter_by(username=username).first()

    if not user:
        flash("User not found!", "danger")
        return redirect(url_for('register'))

    # Check if OTP is expired (5 minutes expiration time)
    otp_expired = (int(time.time()) - user.otp_timestamp) > 300  # 5 minutes = 300 seconds
    if otp_expired:
        flash("OTP has expired. Please try again.", "danger")
        return redirect(url_for('register'))

    if request.method == 'POST':
        entered_otp = request.form['otp']
        if int(entered_otp) == user.otp:
            # OTP is correct, mark user as verified (remove OTP from the database)
            user.otp = None
            user.otp_timestamp = None
            db.session.commit()
            flash("Registration successful! Please login.", "success")
            return redirect(url_for('login'))
        else:
            flash("Invalid OTP. Try again.", "danger")

    return render_template('otp.html', username=username)

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        phone_number = request.form['phone_number']

        # Check for login attempts
        if username not in attempts_db:
            attempts_db[username] = 0

        if attempts_db[username] >= 4:
            flash("Maximum login attempts reached. Try again later.", "danger")
            return redirect(url_for('login'))

        # Retrieve the user from the database
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password_hash, password) and user.phone_number == phone_number:
            # Reset login attempts on successful login
            attempts_db[username] = 0
            session['username'] = username
            flash(f"Welcome {username}!", "success")
            return redirect(url_for('dashboard'))
        else:
            attempts_db[username] += 1
            flash(f"Invalid credentials. Attempt {attempts_db[username]} of 4.", "danger")

    return render_template('login.html')

# Dashboard route after successful login
@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    return f"Welcome to your dashboard, {session['username']}!"

# Logout route
@app.route('/logout')
def logout():
    session.pop('username', None)
    flash("Logged out successfully.", "success")
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
