from flask import Flask, render_template, request, jsonify, url_for, redirect
import mysql.connector
import hashlib
import os
import json
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.image import MIMEImage
from pathlib import Path
from base64 import urlsafe_b64encode, urlsafe_b64decode
import secrets
import sqlite3
import time
from scripts.createAccount import create_account
from scripts.initialize_db import initialize_db

app = Flask(__name__)

# Initialize the SQLite database
initialize_db()

def get_db_connection():
    script_dir = Path(__file__).resolve().parent
    config_path = script_dir / "config.json"

    with open(config_path) as config_file:
        config = json.load(config_file)
    
    return mysql.connector.connect(
        host=config["SERVER_IP"],
        user=config["USERNAME"],
        password=config["PASSWORD"],
        database=config["DATABASE"],
        port=config["MYSQL_PORT"]
    )

def get_sqlite_connection():
    return sqlite3.connect('tokens.db')

def get_config():
    script_dir = Path(__file__).resolve().parent
    config_path = script_dir / "config.json"
    
    with open(config_path) as config_file:
        return json.load(config_file)

@app.route('/')
def home():
    return render_template('accountcreation.html')

@app.route('/resetpassword')
def reset_password():
    return render_template('resetpassword.html')

@app.route('/success')
def success():
    return render_template('success.html')

@app.route('/newpassword')
def new_password():
    token = request.args.get('token')
    email = request.args.get('email')
    
    if not token or not email:
        return "Invalid or expired reset link.", 400
    
    try:
        decoded_email = urlsafe_b64decode(email.encode()).decode()
    except Exception as e:
        return "Invalid or expired reset link.", 400

    conn = get_sqlite_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT email FROM password_reset_tokens WHERE token = ? AND email = ? AND created_at > datetime('now', '-1 hour')", (token, decoded_email))
    token_info = cursor.fetchone()
    conn.close()

    if not token_info:
        return "Invalid or expired reset link.", 400

    return render_template('newpassword.html', email=decoded_email, token=token)

@app.route('/create_account', methods=['POST'])
def handle_create_account():
    data = request.get_json()
    account_name = data['accountName']
    email = data['email']
    passwd1 = data['passwd1']
    passwd2 = data['passwd2']
    expansion = data['expansion']

    result = create_account(account_name, email, passwd1, passwd2, expansion)
    return jsonify({'message': result})

@app.route('/reset_password', methods=['POST'])
def reset_password_request():
    data = request.json
    email = data.get('email')
    
    if not email:
        return jsonify({'message': 'Email is required.'}), 400
    
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    try:
        cursor.execute("SELECT id FROM account WHERE email = %s", (email,))
        account = cursor.fetchone()
        
        if not account:
            return jsonify({'message': 'Email not found.'}), 404
        
        token = secrets.token_urlsafe(16)
        encoded_email = urlsafe_b64encode(email.encode()).decode()

        sqlite_conn = get_sqlite_connection()
        sqlite_cursor = sqlite_conn.cursor()
        sqlite_cursor.execute("INSERT INTO password_reset_tokens (email, token) VALUES (?, ?)", (email, token))
        sqlite_conn.commit()
        sqlite_conn.close()

        reset_link = url_for('new_password', token=token, email=encoded_email, _external=True)
        disable_link = url_for('disable_token', token=token, email=encoded_email, _external=True)
        
        send_email(email, reset_link, disable_link, 'Azerothcore Password Reset Request')
        
        return jsonify({'message': 'Password reset link has been sent to your email.'})
    
    except mysql.connector.Error as err:
        return jsonify({'message': str(err)}), 500
    
    finally:
        cursor.close()
        conn.close()

@app.route('/disable_token', methods=['GET'])
def disable_token():
    token = request.args.get('token')
    email = request.args.get('email')
    
    if not token or not email:
        return jsonify({'message': 'Invalid request.'}), 400
    
    try:
        decoded_email = urlsafe_b64decode(email.encode()).decode()
    except Exception as e:
        return jsonify({'message': 'Invalid request.'}), 400

    conn = get_sqlite_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("DELETE FROM password_reset_tokens WHERE token = ? AND email = ?", (token, decoded_email))
        conn.commit()
        
        if cursor.rowcount == 0:
            return jsonify({'message': 'Token not found or already disabled.'}), 404
        
        return jsonify({'message': 'Token disabled successfully.'}), 200
    
    except sqlite3.Error as err:
        return jsonify({'message': str(err)}), 500
    
    finally:
        cursor.close()
        conn.close()

@app.route('/update_password', methods=['POST'])
def update_password():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    token = data.get('token')
    
    if not email or not password or not token:
        return jsonify({'message': 'All fields are required.'}), 400
    
    if len(password) < 8:
        return jsonify({'message': 'Password must be at least 8 characters long.'}), 400
    
    try:
        decoded_email = urlsafe_b64decode(email.encode()).decode()
    except Exception as e:
        return jsonify({'message': 'Invalid or expired token.'}), 400

    conn = get_sqlite_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT email FROM password_reset_tokens WHERE token = ? AND email = ? AND created_at > datetime('now', '-1 hour')", (token, decoded_email))
    token_info = cursor.fetchone()

    if not token_info:
        conn.close()
        return jsonify({'message': 'Invalid or expired token.'}), 400

    cursor.execute("DELETE FROM password_reset_tokens WHERE token = ? AND email = ?", (token, decoded_email))
    conn.commit()
    conn.close()
    
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    try:
        cursor.execute("SELECT username FROM account WHERE email = %s", (decoded_email,))
        account = cursor.fetchone()
        
        if not account:
            return jsonify({'message': 'Account not found.'}), 404
        
        username = account['username']
        salt = os.urandom(32)
        verifier = calculate_verifier(username, password, salt)
        
        cursor.execute("UPDATE account SET salt = %s, verifier = %s WHERE email = %s", (salt, verifier, decoded_email))
        conn.commit()
        
        send_email(decoded_email, "", "", 'Password Changed', 'Your password has been successfully changed.')
        
        return jsonify({'message': 'Password updated successfully!'})
    
    except mysql.connector.Error as err:
        return jsonify({'message': str(err)}), 500
    
    finally:
        cursor.close()
        conn.close()

def send_email(to_email, reset_link, disable_link, subject):
    config = get_config()
    from_email = config["SMTP_EMAIL_ADDRESS"]
    from_password = config["SMTP_EMAIL_PASSWORD"]

    msg = MIMEMultipart('alternative')
    msg['From'] = from_email
    msg['To'] = to_email
    msg['Subject'] = subject

    text_content = f'Click the link to reset your password: {reset_link}'
    html_content = f"""
    <html>
    <body style="font-family: Arial, sans-serif; background-image: url('cid:background'); background-size: cover; padding: 20px;">
        <div style="max-width: 600px; margin: 0 auto; background: rgba(0, 0, 0, 0.8); padding: 20px; border-radius: 10px; box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);">
            <h2 style="color: #fff;">Password Reset Request</h2>
            <p style="color: #fff;">Click the button below to reset your password:</p>
            <a href="{reset_link}" style="display: inline-block; padding: 10px 20px; font-size: 16px; text-transform: uppercase; font-weight: bold; color: white; background-color: #007bff; text-decoration: none; border-radius: 5px;">Reset Password</a>
            <p style="color: #fff;">If you did not request this email, click the button below to disable the token:</p>
            <a href="{disable_link}" style="display: inline-block; padding: 10px 20px; font-size: 16px; text-transform: uppercase; font-weight: bold; color: white; background-color: #ff0000; text-decoration: none; border-radius: 5px;">Disable Token</a>
            <p style="color: #ccc; margin-top: 20px;">If you have any questions, feel free to contact our support team.</p>
        </div>
    </body>
    </html>
    """

    part1 = MIMEText(text_content, 'plain')
    part2 = MIMEText(html_content, 'html')
    
    # Attach the background image
    with open("static/images/resetemail.png", "rb") as img_file:
        img = MIMEImage(img_file.read())
        img.add_header('Content-ID', '<background>')
        msg.attach(img)

    msg.attach(part1)
    msg.attach(part2)

    try:
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login(from_email, from_password)
            server.sendmail(from_email, to_email, msg.as_string())
        return True
    except Exception as e:
        print(f"Failed to send email: {e}")
        return False

def calculate_verifier(username, password, salt):
    g = 7
    N = int("894B645E89E1535BBDAD5B8B290650530801B18EBFBF5E8FAB3C82872A3E9BB7", 16)
    
    username = username.upper()
    password = password.upper()

    h1 = hashlib.sha1(f"{username}:{password}".encode()).digest()
    h2 = hashlib.sha1(salt + h1).digest()
    
    h2_int = int.from_bytes(h2, 'little')
    verifier_int = pow(g, h2_int, N)
    
    verifier = verifier_int.to_bytes((verifier_int.bit_length() + 7) // 8, 'little')
    return verifier

if __name__ == '__main__':
    app.run(debug=True)
