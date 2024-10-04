import mysql.connector
import hashlib
import os
import json
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask import Flask, request, render_template, jsonify, url_for

app = Flask(__name__)

def get_db_connection():
    script_dir = Path(__file__).resolve().parent
    config_path = script_dir / "../config.json"

    with open(config_path) as config_file:
        config = json.load(config_file)
    
    return mysql.connector.connect(
        host=config["SERVER_IP"],
        user=config["USERNAME"],
        password=config["PASSWORD"],
        database=config["DATABASE"],
        port=config["MYSQL_PORT"]
    )

def get_config():
    script_dir = Path(__file__).resolve().parent
    config_path = script_dir / "../config.json"
    
    with open(config_path) as config_file:
        return json.load(config_file)

@app.route('/resetpassword')
def reset_password():
    return render_template('resetpassword.html')

@app.route('/reset_password', methods=['POST'])
def handle_reset_password():
    data = request.json
    email = data.get('email')
    
    if not email:
        return jsonify({'success': False, 'message': 'Email is required.'}), 400
    
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    try:
        cursor.execute("SELECT id FROM account WHERE email = %s", (email,))
        account = cursor.fetchone()
        
        if not account:
            return jsonify({'success': False, 'message': 'Email not found.'}), 404
        
        token = os.urandom(24).hex()
        
        cursor.execute(
            "INSERT INTO password_reset_tokens (account_id, token) VALUES (%s, %s)",
            (account['id'], token)
        )
        conn.commit()
        
        reset_link = url_for('reset_password_token', token=token, _external=True)
        disable_link = url_for('disable_token', token=token, email=email, _external=True)
        
        send_email(email, reset_link, disable_link, 'Azerothcore Password Reset Request')
        
        return jsonify({'success': True, 'message': 'Password reset link has been sent to your email.'})
    
    except mysql.connector.Error as err:
        return jsonify({'success': False, 'message': str(err)}), 500
    
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
    <body style="font-family: Arial, sans-serif; background-color: #f4f4f4; padding: 20px;">
        <div style="max-width: 600px; margin: 0 auto; background: white; padding: 20px; border-radius: 10px; box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);">
            <h2 style="color: #333;">Password Reset Request</h2>
            <p>Click the button below to reset your password:</p>
            <a href="{reset_link}" style="display: inline-block; padding: 10px 20px; font-size: 16px; text-transform: uppercase; font-weight: bold; color: white; background-color: #007bff; text-decoration: none; border-radius: 5px;">Reset Password</a>
            <p>If you did not request this email, click the button below to disable the token:</p>
            <a href="{disable_link}" style="display: inline-block; padding: 10px 20px; font-size: 16px; text-transform: uppercase; font-weight: bold; color: white; background-color: #ff0000; text-decoration: none; border-radius: 5px;">Disable Token</a>
            <p style="color: #999; margin-top: 20px;">If you have any questions, feel free to contact our support team.</p>
        </div>
    </body>
    </html>
    """

    part1 = MIMEText(text_content, 'plain')
    part2 = MIMEText(html_content, 'html')

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

@app.route('/disable_token', methods=['GET'])
def disable_token():
    token = request.args.get('token')
    email = request.args.get('email')
    
    if not token or not email:
        return jsonify({'message': 'Invalid request.'}), 400
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("DELETE FROM password_reset_tokens WHERE token = %s AND email = %s", (token, email))
        conn.commit()
        
        if cursor.rowcount == 0:
            return jsonify({'message': 'Token not found or already disabled.'}), 404
        
        return jsonify({'message': 'Token disabled successfully.'}), 200
    
    except mysql.connector.Error as err:
        return jsonify({'message': str(err)}), 500
    
    finally:
        cursor.close()
        conn.close()

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password_token(token):
    if request.method == 'POST':
        data = request.form
        password = data.get('password')
        confirm_password = data.get('confirm_password')
        
        if not password or not confirm_password:
            return render_template('resetpassword.html', message='All fields are required.')
        
        if password != confirm_password:
            return render_template('resetpassword.html', message='Passwords do not match.')
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute("SELECT account_id FROM password_reset_tokens WHERE token = %s", (token,))
            result = cursor.fetchone()
            
            if not result:
                return render_template('resetpassword.html', message='Invalid or expired token.')
            
            account_id = result[0]
            salt = os.urandom(32)
            verifier = calculate_verifier("USERNAME", password, salt) # Update USERNAME appropriately
            
            cursor.execute(
                "UPDATE account SET salt = %s, verifier = %s WHERE id = %s",
                (salt, verifier, account_id)
            )
            conn.commit()
            
            cursor.execute("DELETE FROM password_reset_tokens WHERE token = %s", (token,))
            conn.commit()
            
            return redirect(url_for('success'))
        
        finally:
            cursor.close()
            conn.close()
    
    return render_template('resetpassword.html')

@app.route('/success')
def success():
    return render_template('success.html')

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
