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
import base64
import logging

# Set up logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Helper function to check if a string is base64-encoded
def is_base64_encoded(s):
    try:
        if isinstance(s, str):
            s = s.encode('utf-8')
        return base64.urlsafe_b64encode(base64.urlsafe_b64decode(s)) == s
    except Exception:
        return False



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

    # Check if the email or account name already exists in the database
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # Check if the account name or email already exists
        cursor.execute("SELECT id FROM account WHERE username = %s OR email = %s", (account_name, email))
        existing_account = cursor.fetchone()

        if existing_account:
            return jsonify({'message': 'Sorry, either the account name or email is already in use.'}), 400

    except mysql.connector.Error as err:
        return jsonify({'message': f'Database error: {str(err)}'}), 500

    finally:
        cursor.close()
        conn.close()

    # Proceed with account creation if the email and account name are not already in use
    result = create_account(account_name, email, passwd1, passwd2, expansion)

    # Send a confirmation email after account creation
    send_email('new_account', email, "", 'Account Created', 'Your account has been successfully created.')

    return jsonify({'message': result}), 201

@app.route('/reset_password', methods=['POST'])
def reset_password_request():
    data = request.json
    email = data.get('email')
    
    # Validate email input
    if not email:
        return jsonify({'message': 'Email is required.'}), 400
    
    # Get MySQL database connection
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    try:
        # Check if email exists in the account table
        cursor.execute("SELECT id FROM account WHERE email = %s", (email,))
        account = cursor.fetchone()
        
        if not account:
            return jsonify({'message': 'Email not found.'}), 404
        
        # Generate secure token and base64 encode the email
        token = secrets.token_urlsafe(16)
        encoded_email = urlsafe_b64encode(email.encode()).decode()

        # Insert token into SQLite database
        sqlite_conn = get_sqlite_connection()
        with sqlite_conn:
            sqlite_cursor = sqlite_conn.cursor()
            sqlite_cursor.execute(
                "INSERT INTO password_reset_tokens (email, token) VALUES (?, ?)", 
                (email, token)
            )
        
        # Generate reset and disable token links
        reset_link = url_for('new_password', token=token, email=encoded_email, _external=True)
        disable_link = url_for('disable_token', token=token, email=encoded_email, _external=True)
        
        # Send the reset password email
        send_email(
            email_template='reset_password', 
            to_email=email, 
            reset_link=reset_link, 
            disable_link=disable_link, 
            subject='AzerothCore Password Reset Request'
        )
        
        return jsonify({'message': 'Password reset link has been sent to your email.'}), 200
    
    except mysql.connector.Error as err:
        return jsonify({'message': f'Database error: {str(err)}'}), 500
    
    except sqlite3.Error as err:
        return jsonify({'message': f'SQLite error: {str(err)}'}), 500
    
    except Exception as e:
        return jsonify({'message': f'An unexpected error occurred: {str(e)}'}), 500
    
    finally:
        # Ensure both database connections are closed
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

    # Log the incoming data to inspect the request
    logging.debug(f"Incoming POST data: {data}")
    
    email = data.get('email')
    password = data.get('password')
    token = data.get('token')

    # Validate input fields
    if not email or not password or not token:
        logging.warning("Missing fields in the request data.")
        return jsonify({'message': 'All fields (email, password, token) are required.'}), 400

    # Validate password length
    if len(password) < 8:
        logging.warning("Password length is less than 8 characters.")
        return jsonify({'message': 'Password must be at least 8 characters long.'}), 400

    # Attempt to decode base64 email
    try:
        decoded_email = urlsafe_b64decode(email.encode()).decode() if is_base64_encoded(email) else email
        logging.debug(f"Decoded email: {decoded_email}, Token: {token}")
    except Exception as e:
        logging.error("Error decoding email", exc_info=True)
        return jsonify({'message': 'Invalid or expired token.'}), 400

    # Validate token from SQLite database
    try:
        conn = get_sqlite_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT email FROM password_reset_tokens WHERE token = ? AND email = ? AND created_at > datetime('now', '-1 hour')", (token, decoded_email))
        token_info = cursor.fetchone()

        if not token_info:
            logging.warning(f"Invalid or expired token for email: {decoded_email}")
            return jsonify({'message': 'Invalid or expired token.'}), 400

        # Delete token after it's been used
        cursor.execute("DELETE FROM password_reset_tokens WHERE token = ? AND email = ?", (token, decoded_email))
        conn.commit()
    except sqlite3.Error as err:
        logging.error(f"SQLite error during token validation: {err}")
        return jsonify({'message': 'Database error occurred while validating the token.'}), 500
    finally:
        cursor.close()
        conn.close()

    # Update the password in the MySQL database
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("SELECT username FROM account WHERE email = %s", (decoded_email,))
        account = cursor.fetchone()

        if not account:
            logging.warning(f"Account not found for email: {decoded_email}")
            return jsonify({'message': 'Account not found.'}), 404

        username = account['username']
        salt = os.urandom(32)
        verifier = calculate_verifier(username, password, salt)

        cursor.execute("UPDATE account SET salt = %s, verifier = %s WHERE email = %s", (salt, verifier, decoded_email))
        conn.commit()

        # Send confirmation email after successful password update
        send_email(
            email_template='password_updated', 
            to_email=decoded_email, 
            reset_link='', 
            disable_link='', 
            subject='Password Changed',
        )

        logging.info(f"Password updated successfully for email: {decoded_email}")
        return jsonify({'message': 'Password updated successfully!'}), 200

    except mysql.connector.Error as err:
        logging.error(f"MySQL error during password update: {err}")
        return jsonify({'message': f'Database error: {str(err)}'}), 500
    finally:
        cursor.close()
        conn.close()

    return jsonify({'message': 'Unexpected error occurred.'}), 500


def send_email(email_template, to_email, reset_link, disable_link, subject):
    try:
        config = get_config()
        from_email = config["SMTP_EMAIL_ADDRESS"]
        from_password = config["SMTP_EMAIL_PASSWORD"]

        # Create message container
        msg = MIMEMultipart('alternative')
        msg['From'] = from_email
        msg['To'] = to_email
        msg['Subject'] = subject

        if email_template == 'reset_password':
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
        elif email_template == 'new_account':
            text_content = 'Welcome to the World of Warcraft adventure!'
            html_content = f"""
            <html>
            <body style="font-family: Arial, sans-serif; background-image: url('cid:background'); background-size: cover; padding: 20px;">
                <div style="max-width: 600px; margin: 0 auto; background: rgba(0, 0, 0, 0.8); padding: 20px; border-radius: 10px; box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);">
                    <h2 style="color: #fff;">New Account Created</h2>
                    <p style="color: #fff;">Your World of Warcraft account has been successfully created! Welcome to the adventure.</p>

                    <p style="color: #fff;">To get started, we recommend installing some helpful addons:</p>
                    <a href="https://legacy-wow.com/wotlk-addons/" style="display: inline-block; padding: 10px 20px; font-size: 16px; text-transform: uppercase; font-weight: bold; color: white; background-color: #28a745; text-decoration: none; border-radius: 5px;">Install Addons</a>

                    <p style="color: #fff; margin-top: 20px;">Also, check out Wowhead for useful guides and tips:</p>
                    <a href="https://www.wowhead.com/wotlk" style="display: inline-block; padding: 10px 20px; font-size: 16px; text-transform: uppercase; font-weight: bold; color: white; background-color: #007bff; text-decoration: none; border-radius: 5px;">Visit Wowhead</a>

                    <p style="color: #fff; margin-top: 20px;">Don't forget to download the game! Click below to get started:</p>
                    <a href="https://drive.google.com/file/d/1W42A5Th1z470A-3Cz_CJVzKOTGhgjI01/view?usp=sharing" style="display: inline-block; padding: 10px 20px; font-size: 16px; text-transform: uppercase; font-weight: bold; color: white; background-color: #ffc107; text-decoration: none; border-radius: 5px;">Download the Game</a>

                    <p style="color: #ccc; margin-top: 20px;">If you have any questions, feel free to contact our support team.</p>
                </div>
            </body>
            </html>
            """
        elif email_template == 'password_changed':
            text_content = "Your password has been successfully changed."
            html_content = f"""
            <html>
            <body style="font-family: Arial, sans-serif; background-image: url('cid:background'); background-size: cover; padding: 20px;">
                <div style="max-width: 600px; margin: 0 auto; background: rgba(0, 0, 0, 0.8); padding: 20px; border-radius: 10px; box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);">
                    <h2 style="color: #fff;">Password Successfully Changed</h2>
                    <p style="color: #fff;">This is a confirmation that the password for your World of Warcraft account has been successfully updated.</p>
                    <p style="color: #fff;">If you did not make this change, please contact our support team immediately.</p>
                    <p style="color: #ccc; margin-top: 20px;">For any other inquiries or assistance, feel free to reach out to our support team.</p>
                    <p style="color: #ccc;">Thank you for playing, and have a great time in Azeroth!</p>
                </div>
            </body>
            </html>
            """
        else:
            raise ValueError("Invalid email template provided")

        # Attach text and HTML content
        part1 = MIMEText(text_content, 'plain')
        part2 = MIMEText(html_content, 'html')
        msg.attach(part1)
        msg.attach(part2)

        # Attach the background image
        with open("static/images/resetemail.png", "rb") as img_file:
            img = MIMEImage(img_file.read())
            img.add_header('Content-ID', '<background>')
            msg.attach(img)

        # Send email via SMTP
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login(from_email, from_password)
            server.sendmail(from_email, to_email, msg.as_string())
        
        logging.info(f"Email sent to {to_email} with subject '{subject}'")
        return True

    except Exception as e:
        logging.error(f"Failed to send email to {to_email}: {e}")
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
    #app.run(host='0.0.0.0', port=5000, ssl_context=('/home/wotlk_webserver/cert/cert.pem', '/home/wotlk_webserver/cert/key.pem'))
    app.run(host='127.0.0.1', port=10001, debug=True)

    #app.run(debug=True)
