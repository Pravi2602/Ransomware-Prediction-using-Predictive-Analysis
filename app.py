from flask import Flask, render_template, request, redirect, flash, url_for
from flask_sqlalchemy import SQLAlchemy
import os
import random
import hashlib
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'your_secret_key'

BASE_DIR = r'C:\Users\PRAVISHKA\OneDrive\Desktop\ransom'
app.template_folder = os.path.join(BASE_DIR, 'templates')
app.static_folder = os.path.join(BASE_DIR, 'static')
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:root@localhost/ransomware_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

# Password model for storing new passwords
class Pass(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    password = db.Column(db.String(200), nullable=False)

# Ransom model for storing file details
class Ransom(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_name = db.Column(db.String(255), nullable=False)
    file_size = db.Column(db.Integer, nullable=False)
    file_extension = db.Column(db.String(50), nullable=False)
    file_hash = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ransomware_detected = db.Column(db.Boolean, nullable=False)
    detection_method = db.Column(db.String(50), nullable=False)
    suspicious_activity = db.Column(db.String(255), nullable=True)
    file_path = db.Column(db.String(255), nullable=False)
    threat_level = db.Column(db.String(50), nullable=False)
    source = db.Column(db.String(100), nullable=True)
    action_taken = db.Column(db.String(100), nullable=True)
    notes = db.Column(db.String(255), nullable=True)

with app.app_context():
    db.create_all()

@app.route('/')
def login():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login_action():
    username = request.form['username']
    password = request.form['password']
    user = User(username=username, password=password)

    db.session.add(user)
    try:
        db.session.commit()
        return redirect(url_for('home'))
    except Exception as e:
        db.session.rollback()
        return f"An error occurred: {str(e)}"

@app.route('/home')
def home():
    return render_template('home.html')

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        file = request.files.get('file')
        if not file or file.filename == '':
            flash('Please upload a file.')
            return redirect(request.url)
        
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(file_path)
        
        # Generate random data for ransomware detection
        file_size = os.path.getsize(file_path)
        file_extension = file.filename.split('.')[-1]
        file_hash = hashlib.sha256(open(file_path, 'rb').read()).hexdigest()  # Generate file hash (SHA-256)
        
        # Randomly set the ransomware detection values
        ransomware_detected = random.choice([True, False])
        detection_method = random.choice(['signature-based', 'heuristic', 'behavioral analysis'])
        suspicious_activity = random.choice([None, 'Encryption attempt detected', 'Unusual file access'])
        threat_level = random.choice(['Low', 'Medium', 'High'])
        source = random.choice(['email attachment', 'downloaded from a website', 'unknown'])
        action_taken = random.choice(['quarantined', 'deleted', 'ignored', 'investigated'])
        notes = random.choice([None, 'No additional notes', 'File flagged for review'])

        # Create a new Ransom object with the data
        ransom_record = Ransom(
            file_name=file.filename,
            file_size=file_size,
            file_extension=file_extension,
            file_hash=file_hash,
            ransomware_detected=ransomware_detected,
            detection_method=detection_method,
            suspicious_activity=suspicious_activity,
            file_path=file_path,
            threat_level=threat_level,
            source=source,
            action_taken=action_taken,
            notes=notes
        )
        
        db.session.add(ransom_record)
        try:
            db.session.commit()
            flash(f'File "{file.filename}" uploaded successfully and data added to database!')
        except Exception as e:
            db.session.rollback()
            flash(f"An error occurred while saving data: {str(e)}")
        
        return redirect(url_for('home'))

    return render_template('upload.html')

@app.route('/password_recovery', methods=['GET', 'POST'])
def password_recovery():
    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if new_password != confirm_password:
            flash("Passwords do not match. Please try again.")
            return redirect(request.url)

        if new_password and confirm_password:
            flash("Password successfully reset!")
            return redirect(url_for('login'))
        else:
            flash("Please enter a valid password.")
            return redirect(request.url)

    return render_template('pass.html')

@app.route('/reset_password', methods=['POST'])
def reset_password():
    new_password = request.form.get('new_password')
    reenter_password = request.form.get('reenter_password')

    if new_password == reenter_password:
        # Save the new password in the 'pass' table
        password_record = Pass(password=new_password)
        db.session.add(password_record)
        
        try:
            db.session.commit()
            flash("Password successfully reset!")  # Flash message
            return redirect(url_for('login'))  # Redirect to login page after success
        except Exception as e:
            db.session.rollback()  # Rollback if an error occurs
            flash(f"An error occurred: {str(e)}")  # Display error message
            return redirect(url_for('password_recovery'))  # Stay on the password reset page
    else:
        flash("Passwords do not match!")  # Flash message if passwords don't match
        return redirect(url_for('password_recovery'))  # Stay on the password reset page

if __name__ == '__main__':
    app.run(debug=True)
