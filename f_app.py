from flask import Flask, render_template, request, session, jsonify, g, redirect, url_for
import mysql.connector
from cryptography.fernet import Fernet
import bcrypt
import jwt
import hashlib
from functools import wraps
import time
import os
from dotenv import load_dotenv


# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)

# Load Fernet Secret Key for encryption/decryption
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise ValueError("SECRET_KEY environment variable not set. Please set it before running the app.")

# Validate Fernet key
try:
    cipher = Fernet(SECRET_KEY.encode())
except ValueError:
    raise ValueError("SECRET_KEY is invalid. Ensure it is a 32-byte base64-encoded string.")

# Load JWT Secret
JWT_SECRET = os.getenv("JWT_SECRET")
if not JWT_SECRET:
    raise ValueError("JWT_SECRET environment variable not set. Please set it before running the app.")

# Database connection setup
def get_db():
    if 'db' not in g:
        g.db = mysql.connector.connect(
            user=os.getenv("DB_USER", "root"),
            password=os.getenv("DB_PASSWORD", ""),
            database=os.getenv("DB_NAME", "dsp_db")
        )
    return g.db

@app.teardown_appcontext
def close_db(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()

# Root route
@app.route('/')
def home():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return "Welcome to the Secure Database API!"

# Decorator for JWT Authentication
def token_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization').split(" ")[1]
        print("token = ",token)
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


# # Token generation endpoint
# @app.route('/get_token', methods=['GET'])
# def get_token():
#     if "user_id" in session:
#         # Generate a token for the logged-in user
#         token = jwt.encode(
#             {
#                 "user_id": session["user_id"],
#                 "role": session["role"],
#                 "exp": time.time() + 3600,
#             },
#             JWT_SECRET,
#             algorithm="HS256"
#         )
#         return jsonify({"token": token})
#     else:
#         return jsonify({"message": "User not logged in"}), 403

@app.route("/dashboard")
def dashboard():
    # Retrieve the token from the query string
    token = request.args.get("token")
    if token:
        try:
            data = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            g.user_id = data["user_id"]
            g.role = data["role"]
        except jwt.ExpiredSignatureError:
            return jsonify({"message": "Token has expired"}), 403
        except jwt.InvalidTokenError:
            return jsonify({"message": "Invalid token"}), 403
    else:
        return jsonify({"message": "Token is missing"}), 403
    
    # Use token data from g (user_id, role)
    templates={"H":"hadmin_data.html","R":"ruser_data.html"}
    if g.role in templates:
        return render_template(templates[g.role],user_id=g.user_id)
    else:
        # If the role is not recognized, return an error message
        return jsonify({"message": "Unauthorized role"}), 403

# User Authentication: Login Route
@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'GET':
        return render_template("login.html")
    username = request.form['username']
    password = request.form['password']

    db = get_db()
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users_info WHERE username = %s", (username,))
    user = cursor.fetchone()

    if user and bcrypt.checkpw(password.encode(), user['password_hash'].encode()):
        token = jwt.encode(
            {'user_id': user['id'], 'role': user['role'], 'exp': time.time() + 3600},
            JWT_SECRET, algorithm='HS256'
        )
        response = jsonify({"message": "Login successful", "token": token})
        return redirect(url_for("dashboard", token=token))
    return jsonify({"message": "Invalid credentials"}), 401

# # Basic Access Control and Query Route
# @app.route('/query', methods=['GET'])
# @token_required
# def query():
#     role = g.role
#     db = get_db()
#     cursor = db.cursor(dictionary=True)

#     if role == 'H':
#         cursor.execute("SELECT * FROM health_info")
#     elif role == 'R':
#         cursor.execute("SELECT id, gender, age, weight, height, health_history FROM health_info")
#     else:
#         return jsonify({"message": "Unauthorized"}), 403

#     results = cursor.fetchall()
#     # Query Integrity: Adding a hash of the results
#     query_hash = hashlib.sha256(str(results).encode()).hexdigest()
#     return jsonify({"data": results, "query_hash": query_hash})


@app.route('/data', methods=['GET','POST'])
@token_required  # Ensure only authenticated users can access this data
def get_data():
    db = get_db()
    cursor = db.cursor(dictionary=True)
    
    try:
        cursor.execute("SELECT * FROM health_info")
        results = cursor.fetchall()
        
    
        return jsonify(results)  # Send the data as JSON
    except Exception as e:
        return jsonify({"message": "Error fetching data", "error": str(e)}), 500
    finally:
        cursor.close()


# Verifying Query Integrity
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

# Running the Flask app
if __name__ == '__main__':
    app.run(debug=True)


