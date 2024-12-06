from flask import Flask, request, jsonify
from datetime import datetime, timedelta
import jwt
import json
import rsa
import base64
import sqlite3
import os
import uuid
from argon2 import PasswordHasher
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from collections import defaultdict
import time

app = Flask(__name__)

DB_NAME = 'totally_not_my_privateKeys.db'
ph = PasswordHasher(time_cost=2, memory_cost=102400, parallelism=8, hash_len=32, salt_len=16)

# Rate limiter configuration
RATE_LIMIT = 1  # Maximum requests
TIME_WINDOW = 1  # Time window in seconds
request_log = defaultdict(list)  # Dictionary to store request timestamps for each IP


#this will be our function to chekc if a current ip address has hit their limit. 
def is_rate_limited(ip):
    """Check if the IP address has exceeded the rate limit."""
    current_time = time.time()
    request_log[ip] = [timestamp for timestamp in request_log[ip] if current_time - timestamp < TIME_WINDOW]

    if len(request_log[ip]) >= RATE_LIMIT:
        return True
    request_log[ip].append(current_time)
    return False



def pad_data(data: bytes) -> bytes:
    """Pad data to be a multiple of AES block size."""
    padder = padding.PKCS7(128).padder()  # AES block size is 128 bits = 16 bytes
    return padder.update(data) + padder.finalize()

def unpad_data(data: bytes) -> bytes:
    """Unpad decrypted data."""
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(data) + unpadder.finalize()

#intiail funciton to get the database setup
def init_db():
    """Initialize the SQLite database and create the tables if they don't exist."""
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        
        # Create keys table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS keys(
                kid INTEGER PRIMARY KEY AUTOINCREMENT,
                key BLOB NOT NULL,
                exp INTEGER NOT NULL
            )
        """)
        
        # Create users table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                email TEXT UNIQUE,
                date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP
            )
        """)
        
        # Create auth_logs table for logging authentication requests
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS auth_logs(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_ip TEXT NOT NULL,
                request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                user_id INTEGER,  
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        """)
        conn.commit()


#this will be called to get the public and private keys and put them into the database. 
def load_or_generate_keys():
    """Load private and public keys from the database, or generate new ones if they don't exist."""
    encryption_key = os.environ.get('NOT_MY_KEY')
    if not encryption_key:
        raise ValueError("Environment variable 'NOT_MY_KEY' not set")
    encryption_key = encryption_key.encode()

    with sqlite3.connect(DB_NAME) as conn:  #connect to the database
        cursor = conn.cursor()
        cursor.execute("SELECT key FROM keys WHERE exp > ?", (int(datetime.utcnow().timestamp()),))
        row = cursor.fetchone()

        if row:
            encrypted_private_key = row[0]  #retrieve the private key from the database and decrypt it 
            private_key_pem = decrypt_private_key(encrypted_private_key, encryption_key)
            private_key = rsa.PrivateKey.load_pkcs1(private_key_pem)
            public_key = rsa.PublicKey(private_key.n, private_key.e)
            return private_key, public_key
        else:
               #generate new keys and save them to the database, now we also encrypt them.
            (public_key, private_key) = rsa.newkeys(2048)
            private_key_pem = private_key.save_pkcs1()
            encrypted_private_key = encrypt_private_key(private_key_pem, encryption_key)
            cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", 
                           (encrypted_private_key, int((datetime.utcnow() + timedelta(days=365)).timestamp())))
            conn.commit()
            return private_key, public_key

def encrypt_private_key(private_key_pem: bytes, encryption_key: bytes) -> bytes:
    """Encrypt the private key using AES encryption."""
    padded_data = pad_data(private_key_pem)

    #use the cipher library to encrypt the keys. 
    cipher = Cipher(algorithms.AES(encryption_key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    return encrypted_data

def decrypt_private_key(encrypted_data: bytes, encryption_key: bytes) -> bytes:
    """Decrypt the encrypted private key using AES."""
    
    cipher = Cipher(algorithms.AES(encryption_key), modes.ECB(), backend=default_backend())

    #decrypt using cipher lib.
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    return unpad_data(decrypted_data)

#function to base64url encode a number
def base64url_encode(value):
    """Encodes a value to base64url."""
    return base64.urlsafe_b64encode(value.to_bytes((value.bit_length() + 7) // 8, byteorder='big')).decode('utf-8').rstrip('=')

init_db()
private_key, public_key = load_or_generate_keys()

#define jwt's
JWK_KEYS = {
    "keys": [
        {
            "kty": "RSA",
            "alg": "RS256", 
            "kid": "unique-key-id",  
            "use": "sig",
            "n": base64url_encode(public_key.n),
            "e": base64url_encode(65537) 
        }
    ]
}

def log_authentication_request(username: str, request_ip: str):
    """Logs the authentication attempt in the 'auth_logs' table."""
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        
        if user:
            user_id = user[0]
            cursor.execute("""
                INSERT INTO auth_logs (request_ip, user_id) 
                VALUES (?, ?)
            """, (request_ip, user_id))
            conn.commit()
        else:
            cursor.execute("""
                INSERT INTO auth_logs (request_ip, user_id) 
                VALUES (?, NULL)  # NULL as user_id if user is not found
            """, (request_ip,))
            conn.commit()


#auth endpoint
@app.route('/auth', methods=['POST'])
def auth():
    client_ip = request.remote_addr
    #first we just check if the user is allowed to make any more requests using their ip address passed to our function.
    if is_rate_limited(client_ip):
        return jsonify({"message": "Too many requests, please try again later"}), 429 #retrun 429 if they cant do anymopre. 

    username = request.json.get('username')
    password = request.json.get('password')
    expired = request.args.get('expired')  #check for 'expired' query parameter

    if username == 'userABC' and password == 'password123':
        #determine expiration time based on the 'expired' parameter
        expiration = datetime.utcnow() - timedelta(minutes=10) if expired == 'true' else datetime.utcnow() + timedelta(minutes=10)
        headers = {"kid": "unique-key-id"}
        token = jwt.encode({'exp': expiration}, private_key, algorithm='RS256', headers=headers)

        # Log the authentication attempt
        log_authentication_request(username, client_ip)

        return jsonify(token=token), 200
    else:
        log_authentication_request(username, client_ip)  # Log failed login attempt as well
        return jsonify({"message": "Invalid credentials"}), 401  # 401 instead of 200 for invalid credentials


#other endpoint that returns list of keys. 
@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks():
    return jsonify(JWK_KEYS), 200

#endpoint to decode key
@app.route('/secure-endpoint', methods=['GET'])
def secure_endpoint():
    token = request.headers.get('Authorization').split()[1]
    try:
        payload = jwt.decode(token, public_key, algorithms=['RS256'])
        return jsonify({"message": "Token is valid", "payload": payload}), 200
    except jwt.ExpiredSignatureError:
        return jsonify({"message": "Token has expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"message": "Invalid token"}), 401
        
#new register endpoint
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')

    if not username or not email:
        return jsonify({"message": "Username and email are required"}), 400

    password = str(uuid.uuid4())
    try:
        password_hash = ph.hash(password)
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor() #when someone registers with a usename passwords and email we will send that to db
            cursor.execute("INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)", 
                           (username, password_hash, email))
            conn.commit()
        return jsonify({"password": password}), 201
    except sqlite3.IntegrityError as e:
        if "UNIQUE constraint failed" in str(e):
            return jsonify({"message": "Username or email already exists"}), 409
        return jsonify({"message": "Database error"}), 200
    except Exception as e:
        return jsonify({"message": "An error occurred", "error": str(e)}), 200

if __name__ == '__main__':
    app.run(port=8080)
