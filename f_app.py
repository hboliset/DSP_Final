from flask import Flask, request, jsonify, g
import mysql.connector
from cryptography.fernet import Fernet
import bcrypt
import jwt
import hashlib
from functools import wraps
import time
import os

# Initialize Flask app
app = Flask(__name__)

# Encryption and Decryption Setup
SECRET_KEY = Fernet.generate_key()
cipher = Fernet(SECRET_KEY)

# JWT Secret for Encoding/Decoding tokens
JWT_SECRET = os.getenv("JWT_SECRET")
if not JWT_SECRET:
    raise ValueError("JWT_SECRET environment variable not set. Please set it before running the app.")


# Database connection
def get_db():
    if 'db' not in g:
        g.db = mysql.connector.connect(user='root', password='mysqlgit15', database='dsp_db')
    return g.db

@app.teardown_appcontext
def close_db(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()

# Root route
@app.route('/')
def home():
    return "Welcome to the Secure Database API!" 

# Decorator for JWT Authentication
def token_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({"message": "Token is missing"}), 403
        try:
            data = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            g.user_id = data['user_id']
            g.role = data['role']
        except jwt.ExpiredSignatureError:
            return jsonify({"message": "Token has expired"}), 403
        except jwt.InvalidTokenError:
            return jsonify({"message": "Invalid token"}), 403
        return f(*args, **kwargs)
    return decorated_function

# User Authentication: Login Route
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data['username']
    password = data['password']

    db = get_db()
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users_info WHERE username = %s", (username,))
    user = cursor.fetchone()

    if user and bcrypt.checkpw(password.encode(), user['password_hash'].encode()):
        token = jwt.encode(
            {'user_id': user['id'], 'role': user['role'], 'exp': time.time() + 3600},
            JWT_SECRET, algorithm='HS256'
        )
        return jsonify({"message": "Login successful", "token": token})
    return jsonify({"message": "Invalid credentials"}), 401

# Basic Access Control and Query Route
@app.route('/query', methods=['GET'])
@token_required
def query():
    role = g.role
    db = get_db()
    cursor = db.cursor(dictionary=True)

    if role == 'H':
        cursor.execute("SELECT * FROM health_info")
    elif role == 'R':
        cursor.execute("SELECT id, gender, age, weight, height, health_history FROM health_info")
    else:
        return jsonify({"message": "Unauthorized"}), 403

    results = cursor.fetchall()
    # Query Integrity: Adding a hash of the results
    query_hash = hashlib.sha256(str(results).encode()).hexdigest()
    return jsonify({"data": results, "query_hash": query_hash})

# Data Insertion Route (Only for 'H' Role)
@app.route('/insert', methods=['POST'])
@token_required
def insert():
    if g.role != 'H':
        return jsonify({"message": "Unauthorized"}), 403

    data = request.json

    # Encrypt Sensitive Data (Gender, Age)
    encrypted_gender = cipher.encrypt(str(data['gender']).encode())
    encrypted_age = cipher.encrypt(str(data['age']).encode())

    db = get_db()
    cursor = db.cursor()
    cursor.execute("INSERT INTO health_info (first_name, last_name, gender, age, weight, height, health_history) VALUES (%s, %s, %s, %s, %s, %s, %s)",
                   (data['first_name'], data['last_name'], encrypted_gender, encrypted_age, data['weight'], data['height'], data['health_history']))
    db.commit()

    return jsonify({"message": "Data inserted successfully"})

# Data Encryption for Sensitive Fields
@app.route('/get_sensitive_data', methods=['GET'])
@token_required
def get_sensitive_data():
    db = get_db()
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT id, gender, age, weight, height, health_history FROM health_info")
    results = cursor.fetchall()

    # Decrypt sensitive fields before returning them
    for record in results:
        record['gender'] = cipher.decrypt(record['gender']).decode()
        record['age'] = cipher.decrypt(record['age']).decode()

    return jsonify(results)

# Protect Query Integrity: Verifying Data Hash
@app.route('/verify_query', methods=['POST'])
@token_required
def verify_query():
    data = request.json
    received_hash = data.get('query_hash')
    query_results = data.get('data')

    # Calculate the hash of the received query data
    calculated_hash = hashlib.sha256(str(query_results).encode()).hexdigest()

    if received_hash == calculated_hash:
        return jsonify({"message": "Query integrity verified"})
    else:
        return jsonify({"message": "Query integrity failed"}), 400

# Run the Flask app
if __name__ == '__main__':
    app.run(debug=True)
