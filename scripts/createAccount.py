import mysql.connector
import hashlib
import os
import json
from pathlib import Path

def sha1(data):
    return hashlib.sha1(data).digest()

def generate_salt():
    return os.urandom(32)

def calculate_verifier(username, password, salt):
    g = 7
    N = int("894B645E89E1535BBDAD5B8B290650530801B18EBFBF5E8FAB3C82872A3E9BB7", 16)
    
    username = username.upper()
    password = password.upper()

    h1 = sha1(f"{username}:{password}".encode())
    h2 = sha1(salt + h1)
    
    h2_int = int.from_bytes(h2, 'little')
    verifier_int = pow(g, h2_int, N)
    
    verifier = verifier_int.to_bytes((verifier_int.bit_length() + 7) // 8, 'little')
    return verifier

def create_account(account_name, email, passwd1, passwd2, expansion):
    if passwd1 != passwd2:
        return "Passwords do not match."
    
    script_dir = Path(__file__).resolve().parent
    config_path = script_dir / "../config.json"

    with open(config_path) as config_file:
        config = json.load(config_file)
    
    USERNAME = config["USERNAME"]
    PASSWORD = config["PASSWORD"]
    SERVER_IP = config["SERVER_IP"]
    PORT = config["MYSQL_PORT"]
    DATABASE = config["DATABASE"]
    
    conn = None
    cursor = None

    try:
        conn = mysql.connector.connect(
            host=SERVER_IP,
            user=USERNAME,
            password=PASSWORD,
            database=DATABASE,
            port=PORT
        )
        cursor = conn.cursor()

        # Check if the username already exists
        cursor.execute("SELECT id FROM account WHERE username = %s", (account_name,))
        if cursor.fetchone():
            return "Username already taken."

        cursor.execute("SELECT MAX(id) FROM account")
        max_id = cursor.fetchone()[0]
        new_id = max_id + 1 if max_id else 1

        salt = generate_salt()
        verifier = calculate_verifier(account_name, passwd1, salt)
        
        cursor.execute(
            "INSERT INTO account (id, username, salt, verifier, email) VALUES (%s, %s, %s, %s, %s)",
            (new_id, account_name, salt, verifier, email)
        )
        conn.commit()
        
        return "Account created successfully!"
    
    except mysql.connector.Error as err:
        return f"Error: {err}"
    
    finally:
        if cursor is not None:
            cursor.close()
        if conn is not None:
            conn.close()
