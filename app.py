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

#Route to fetch data (GET)

@app.route("/data", methods=["GET","POST"])
@token_required  # Ensure only authenticated users can access this data
def get_data():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({"message": "Token is missing"}), 403
    db = get_db()
    cursor = db.cursor(dictionary=True)

    try:
        cursor.execute("SELECT * FROM health_info")
        results = cursor.fetchall()

        for record in results:
            # Concatenate fields that are part of the hash (adjust based on your requirements)
            data_string = f"{record['first_name']}{record['last_name']}{record['gender']}{record['age']}{record['weight']}{record['height']}{record['health_history']}"
            data_hash = hashlib.sha256(data_string.encode()).hexdigest()

            # Add the datahash to each record
            record['data_hash'] = data_hash


        print(jsonify(results))
        return jsonify(results)  # Send the data as JSON
    except Exception as e:
        return jsonify({"message": "Error fetching data", "error": str(e)}), 500
    finally:
        cursor.close()

#route to insert data (POST)
@app.route("/insert", methods=["POST"])
@token_required  # Ensure only authenticated users can insert data
def insert_data():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({"message": "Token is missing"}), 403

    try:
        data = request.get_json()  # Retrieve the data sent in the request body
        print("Received data:", data)
        conn = get_db()
        cursor = conn.cursor()
        query = """
            INSERT INTO health_info (first_name, last_name, gender, age, weight, height, health_history)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """
        cursor.execute(query, (data['first_name'], data['last_name'], data['gender'], 
                               data['age'], data['weight'], data['height'], data['health_history']))
        conn.commit()
        cursor.close()
        return jsonify({"message": "Data inserted successfully!"}), 201
    except Exception as e:
        print(f"Error inserting data: {str(e)}")  # Log the error for debugging
        return jsonify({"message": "Error inserting data", "error": str(e)}), 500
    
#update code

@app.route("/data/<int:id>", methods=["GET","POST"])
@token_required
def update_data_with_hash_check(id):
    token = request.headers.get('Authorization')
    db = get_db()
    cursor = db.cursor(dictionary=True)

    #Handle GET request
    if request.method == "GET":
        try:
            # Fetch the current record to retrieve the old hash
            cursor.execute("SELECT * FROM health_info WHERE id = %s", (id,))
            data = cursor.fetchone()

            if data:
                return jsonify(data), 200
            
            else:
                return jsonify({"Message": "Data not found"}), 404
        except Exception as e:
            return jsonify({"Message": "Error fetching data", "error": str(e)}), 500
        
    # Handle POST request to update data by ID
    elif request.method == "POST":
        try:
            data = request.get_json()
            if not all(key in data for key in ["first_name", "last_name", "gender", "age", "weight", "height", "health_history"]):
                return jsonify({"message": "Missing required fields"}), 400

            cursor.execute(
                """
                UPDATE health_info
                SET first_name = %s, last_name = %s, gender = %s, age = %s, weight = %s, height = %s, health_history = %s
                WHERE id = %s
                """,
                (data["first_name"], data["last_name"], data["gender"], data["age"], 
                 data["weight"], data["height"], data["health_history"], id),
            )
            db.commit()

            if cursor.rowcount > 0:
                return jsonify({"message": "Data updated successfully"}), 200
            else:
                return jsonify({"message": "No changes made"}), 400
        except Exception as e:
            return jsonify({"message": "Error updating data", "error": str(e)}), 500

    return jsonify({"message": "Method Not Allowed"}), 405






@app.route("/delete/<int:id>", methods=["DELETE"])
@token_required
def delete_data(id):
    db = get_db()
    cursor = db.cursor()

    try:
        cursor.execute("DELETE FROM health_info WHERE id = %s", (id,))
        db.commit()

        if cursor.rowcount > 0:
            return jsonify({"message": "Data deleted successfully"}), 200
        else:
            return jsonify({"message": "No data found for the given ID"}), 404

    except Exception as e:
        return jsonify({"message": "Error deleting data", "error": str(e)}), 500

    finally:
        cursor.close()


# Run the Flask app
if __name__ == "__main__":
    app.run(debug=True)