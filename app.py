from flask import Flask, request, jsonify, send_from_directory, render_template, url_for
from models import db, User  # Import db and User from models.py
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import jwt
import datetime
import re
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask_migrate import Migrate
from flask.cli import with_appcontext
import click

app = Flask(__name__)
# Application Configuration
app.config['SECRET_KEY'] = 'your-secret-key'  # Ensure this is set before use
# Configure database URI
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///signmeup.db'  # Update with your database URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize SQLAlchemy
db.init_app(app)  # Initialize db with app

# Initialize Flask-Migrate
migrate = Migrate(app, db)

# Email Validation Function
def is_valid_email(email):
    email_regex = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return re.match(email_regex, email) is not None

# Authentication Decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('x-access-token')

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.filter_by(id=data['user_id']).first()

            if not current_user:
                return jsonify({'message': 'User not found!'}), 401

        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated

# Send Verification Email
def send_verification_email(email, token):
    sender_email = os.getenv("SENDER_EMAIL")  # Use environment variables
    sender_password = os.getenv("SENDER_PASSWORD")
    subject = "Email Verification"
    body = f"Please verify your email by clicking on the following link: {url_for('verify_email', token=token, _external=True)}"

    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    try:
        # Connect to Gmail's SMTP server
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, email, msg.as_string())
        server.quit()
        print(f"Verification email sent to {email}")
    except Exception as e:
        print(f"Failed to send email: {e}")

# Routes
@app.route('/')
def index():
    return render_template('index.html')  # Landing page

@app.route('/signup_page')
def signup_page():
    return render_template('signup.html')

@app.route('/signin_page')
def signin_page():
    return render_template('signin.html')

@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'message': 'Email and password are required'}), 400

    if not is_valid_email(email):
        return jsonify({'message': 'Invalid email format'}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({'message': 'Email already registered'}), 409

    hashed_password = generate_password_hash(password, method='sha256')
    new_user = User(email=email, password=hashed_password, is_verified=False)
    db.session.add(new_user)
    db.session.commit()

    # Generate verification token
    token = jwt.encode({
        'user_id': new_user.id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }, app.config['SECRET_KEY'], algorithm="HS256")

    send_verification_email(email, token)

    return jsonify({'message': 'Registered successfully, please check your email to verify your account'}), 201

@app.route('/signin', methods=['POST'])
def signin():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'message': 'Email and password are required'}), 400

    user = User.query.filter_by(email=email).first()

    if not user or not check_password_hash(user.password, password):
        return jsonify({'message': 'Invalid email or password'}), 401

    # Generate JWT token
    token = jwt.encode({
        'user_id': user.id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
    }, app.config['SECRET_KEY'], algorithm="HS256")

    return jsonify({'token': token}), 200

@app.route('/verify_email/<token>', methods=['GET'])
def verify_email(token):
    try:
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        user = User.query.filter_by(id=data['user_id']).first()

        if not user:
            return jsonify({'message': 'Invalid token!'}), 401

        user.is_verified = True
        db.session.commit()
        return render_template('verify_email.html', message='Email verified successfully!')

    except jwt.ExpiredSignatureError:
        return render_template('verify_email.html', message='Verification link expired!')
    except jwt.InvalidTokenError:
        return render_template('verify_email.html', message='Invalid token!')

@click.command(name='create_db')
@with_appcontext
def create_database():
    """Create the database and tables."""
    db.create_all()
    click.echo('Database created successfully!')

app.cli.add_command(create_database)

# Run App
if __name__ == '__main__':
    app.run(debug=True)  # Debug mode for development only
