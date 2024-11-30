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
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization


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


#######
# RSA Key Pair Generation (for demonstration; use pre-generated keys in production)
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()
########

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
        token = None
        if "Authorization" in request.headers:
            token = request.headers["Authorization"].split(" ")[1]
        if not token:
            return jsonify({"message": "Token is missing!"}), 403
        try:
            # Decode token and validate here
            decoded = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
            g.user = decoded["user"]
            g.role = decoded["role"]  # Assuming the token has role info
        except jwt.ExpiredSignatureError: 
            return jsonify({"message": "Token has expired!"}), 403 
        except jwt.InvalidTokenError: 
            return jsonify({"message": "Invalid token!"}), 403 
        except Exception as e: 
            return jsonify({"message": "Token verification failed!", "error": str(e)}), 403 
        return f(*args, **kwargs) 
    return decorated_function


# RSA Signature Functions
def sign_hash(data_hash):
    return private_key.sign(
        data_hash.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

def verify_signature(data_hash, signature):
    try:
        public_key.verify(
            signature,
            data_hash.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False


# Merkle Tree Implementation for Query Completeness
class MerkleTree:
    def __init__(self, data):
        self.data = data
        self.tree = []
        self.build_tree()

    def build_tree(self):
        hashes = [hashlib.sha256(str(item).encode()).hexdigest() for item in self.data]
        self.tree.append(hashes)
        while len(hashes) > 1:
            parent_layer = []
            for i in range(0, len(hashes), 2):
                if i + 1 < len(hashes):
                    combined = hashes[i] + hashes[i + 1]
                else:
                    combined = hashes[i]  # Handle odd number of nodes
                parent_layer.append(hashlib.sha256(combined.encode()).hexdigest())
            hashes = parent_layer
            self.tree.append(hashes)

    def get_root(self):
        return self.tree[-1][0] if self.tree else None


# Root route
@app.route("/")
def home():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return "Welcome to the Secure Database API!"


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
        return redirect(url_for("dashboard", token=token))

    # If credentials are incorrect, return an error
    return jsonify({"message": "Invalid credentials"}), 401


@app.route("/dashboard", methods=["GET"])
@token_required
def dashboard():
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


# Route to fetch data
@app.route("/data", methods=["GET"])
@token_required
def get_data():
    db = get_db()  # Assuming you have a `get_db()` function to get the DB connection.
    cursor = db.cursor(dictionary=True)

    try:
        cursor.execute("SELECT * FROM health_info")
        results = cursor.fetchall()
        if not results:
            return jsonify({"message": "No data found"}), 404

        # Encrypt sensitive fields for all users
        for item in results:
            try:
                if g.role == "R":
                    # Remove first name and last name for group R
                    item.pop("first_name", None)
                    item.pop("last_name", None)

                # Decrypt sensitive fields
                item["gender"] = cipher.decrypt(item["gender"].encode()).decode()
                item["age"] = cipher.decrypt(item["age"].encode()).decode()
            except Exception as e:
                app.logger.error(f"Error decrypting fields: {str(e)}")
                return jsonify({"message": "Decryption failed", "error": str(e)}), 500

            try:
                # Serialize and hash data, then sign it
                item_str = str(item)
                item_hash = hashlib.sha256(item_str.encode()).hexdigest()
                item["signature"] = sign_hash(item_hash).hex()
            except Exception as e:
                app.logger.error(f"Error signing data: {str(e)}")
                return jsonify({"message": "Error signing data", "error": str(e)}), 500

        return jsonify(results), 200
    except Exception as e:
        app.logger.error(f"Error fetching data: {str(e)}")
        return jsonify({"message": "Error fetching data", "error": str(e)}), 500
    finally:
        cursor.close()


@app.route("/data/completeness", methods=["GET"])
@token_required
def get_data_with_completeness():
    db = get_db()
    cursor = db.cursor(dictionary=True)

    try:
        cursor.execute("SELECT * FROM health_info")
        results = cursor.fetchall()

        # Build Merkle tree for query results
        data_strings = [str(item) for item in results]
        tree = MerkleTree(data_strings)
        merkle_root = tree.get_root()

        # Return results with Merkle root for completeness verification
        return jsonify({"data": results, "merkle_root": merkle_root}), 200
    except Exception as e:
        return jsonify({"message": "Error fetching data", "error": str(e)}), 500
    finally:
        cursor.close()


@app.route("/insert", methods=["POST"])
@token_required
def insert_data():
    if g.role != "H":
        return jsonify({"message": "Unauthorized role"}), 403

    # Get data from request
    data = request.get_json()
    first_name = data.get("first_name")
    last_name = data.get("last_name")
    gender = data.get("gender")
    age = data.get("age")

    # Encrypt sensitive fields
    encrypted_gender = cipher.encrypt(gender.encode()).decode()
    encrypted_age = cipher.encrypt(str(age).encode()).decode()

    db = get_db()
    cursor = db.cursor()

    try:
        cursor.execute(
            "INSERT INTO health_info (first_name, last_name, gender, age) VALUES (%s, %s, %s, %s)",
            (first_name, last_name, encrypted_gender, encrypted_age),
        )
        db.commit()
        return jsonify({"message": "Data inserted successfully"}), 201
    except Exception as e:
        db.rollback()
        return jsonify({"message": "Error inserting data", "error": str(e)}), 500
    finally:
        cursor.close()


if __name__ == "__main__":
    app.run(debug=True)

