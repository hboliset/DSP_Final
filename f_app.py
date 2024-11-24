from flask import (
    Flask,
    session,
    render_template,
    redirect,
    url_for,
    request,
    jsonify,
    g,
)
import mysql.connector
from cryptography.fernet import Fernet
import bcrypt
import jwt
import hashlib
from functools import wraps
import time
import os
from dotenv import load_dotenv
from flask_cors import CORS
import requests


load_dotenv()
user = os.getenv("DB_USER")
password = os.getenv("DB_PASSWORD")
database = os.getenv("DB_NAME")
# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Encryption and Decryption Setup
FERNET_SECRET = os.getenv("SECRET_KEY")
if not FERNET_SECRET:
    raise ValueError("FERNET_SECRET environment variable not set.")
cipher = Fernet(FERNET_SECRET)

# JWT Secret for Encoding/Decoding tokens
JWT_SECRET = os.getenv("JWT_SECRET")
if not JWT_SECRET:
    raise ValueError("JWT_SECRET environment variable not set.")


# Database connection
def get_db():
    if "db" not in g:
        g.db = mysql.connector.connect(
            user=user, password=password, database=database
        )
    return g.db


@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def token_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            token = request.headers.get("Authorization").split(" ")[1]
        except Exception as e:
            token = request.headers.get("Authorization")
            print("token=",token)
        if not token:
            return jsonify({"message": "Token is missing"}), 403
        try:
            data = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            g.user_id = data["user_id"]
            g.role = data["role"]
            print(g.user_id, g.role)
        except jwt.ExpiredSignatureError:
            return jsonify({"message": "Token has expired"}), 403
        except jwt.InvalidTokenError:
            return jsonify({"message": "Invalid token"}), 403
        return f(*args, **kwargs)

    return decorated_function


# Root route
@app.route("/")
def home():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return "Welcome to the Secure Database API!"


# Decorator for JWT Authentication
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

    # Render the appropriate template based on user role
    templates = {"H": "hadmin_data.html", "R": "ruser_data.html"}
    if g.role in templates:
        return render_template(templates[g.role], user_id=g.user_id)
    return jsonify({"message": "Unauthorized role"}), 403


# User Authentication: Login Route
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")  # Render the login form

    # Extract username and password from the form (or JSON payload)
    username = request.form["username"]
    password = request.form["password"]

    # Connect to the database
    db = get_db()
    cursor = db.cursor(dictionary=True)

    # Query the user record from the database
    cursor.execute("SELECT * FROM users_info WHERE username = %s", (username,))
    user = cursor.fetchone()

    # Check if user exists and password matches
    if user and bcrypt.checkpw(password.encode(), user["password_hash"].encode()):
        # Generate JWT token if login is successful
        token = jwt.encode(
            {"user_id": user["id"], "role": user["role"], "exp": time.time() + 3600},
            JWT_SECRET,
            algorithm="HS256",
        )
        response = jsonify({"message": "Login successful", "token": token})
        print(response)
        return redirect(url_for("dashboard", token=token))

    # If credentials are incorrect, return an error
    return jsonify({"message": "Invalid credentials"}), 401


@app.route("/data", methods=["GET", "POST"])
@token_required  # Ensure only authenticated users can access this data
def get_data():
    db = get_db()
    cursor = db.cursor(dictionary=True)

    try:
        cursor.execute("SELECT * FROM health_info")
        results = cursor.fetchall()

        print(jsonify(results))
        return jsonify(results)  # Send the data as JSON
    except Exception as e:
        return jsonify({"message": "Error fetching data", "error": str(e)}), 500
    finally:
        cursor.close()

@app.route("/data/<int:id>", methods=["GET", "POST"])
@token_required  # Ensure only authenticated users can access this data
def get_data_by_id(id):
    db = get_db()
    cursor = db.cursor(dictionary=True)

    # Handle GET request: Retrieve data for a specific ID
    if request.method == "GET":
        try:
            cursor.execute("SELECT * FROM health_info WHERE id = %s", (id,))
            result = cursor.fetchone()

            if result:
                return jsonify(result), 200  # Return the record if found
            else:
                return jsonify({"message": "Data not found"}), 404

        except Exception as e:
            return jsonify({"message": "Error fetching data", "error": str(e)}), 500

    # Handle POST request: Update data for a specific ID
    if request.method == "POST":
        try:
            # Extract the updated data from the request
            data = request.get_json()

            # You can add validation for the incoming data if necessary
            if not all(key in data for key in ["health_info", "other_field"]):  # Replace with actual fields
                return jsonify({"message": "Missing required fields"}), 400

            # Example query to update the health_info record
            cursor.execute(
                """
                UPDATE health_info
                SET health_info = %s, other_field = %s  # Replace with actual fields
                WHERE id = %s
                """,
                (data["health_info"], data["other_field"], id),
            )
            db.commit()

            if cursor.rowcount > 0:
                return jsonify({"message": "Data updated successfully"}), 200
            else:
                return jsonify({"message": "No changes made"}), 400

        except Exception as e:
            return jsonify({"message": "Error updating data", "error": str(e)}), 500

    return jsonify({"message": "Method Not Allowed"}), 405


# Run the Flask app
if __name__ == "__main__":
    app.run(debug=True)