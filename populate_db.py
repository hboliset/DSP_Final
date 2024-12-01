import mysql.connector
import bcrypt
from cryptography.fernet import Fernet
import hashlib
import random
import os
from dotenv import load_dotenv
import base64

# Load environment variables from .env file
load_dotenv()
user = os.getenv("DB_USER")  # Updated to match the .env variable
password = os.getenv("DB_PASSWORD")  # Updated to match the .env variable
host = os.getenv("HOST")  # This remains the same
database = os.getenv("DB_NAME")  # Updated to match the .env variable
key= os.getenv("KEY").encode()

# Initialize the Fernet cipher
cipher_suite = Fernet(key)

# Predefined lists of names, genders, health history, etc.
first_names = ['John', 'Jane', 'Alice', 'Bob', 'Charlie', 'Diana', 'Eve', 'Frank', 'Grace', 'Hank']
last_names = ['Smith', 'Doe', 'Johnson', 'Williams', 'Brown', 'Jones', 'Garcia', 'Miller', 'Davis', 'Wilson']
genders = [True, False]  # True for male, False for female (or other representations)
ages = list(range(18, 80))  # Age range from 18 to 79
weights = [random.uniform(50, 120) for _ in range(100)]  # Random weights between 50 and 120 kg
heights = [random.uniform(150, 200) for _ in range(100)]  # Random heights between 150 cm and 200 cm
health_histories = [
    "Healthy",
    "Diabetes",
    "Hypertension",
    "Asthma",
    "Allergies",
    "Heart Disease",
    "Arthritis",
    "Obesity",
    "Depression",
    "No significant health history"
]

# Establish MySQL connection
try:
    conn = mysql.connector.connect(user=user, password=password, host=host, database=database)
    cursor = conn.cursor()

    # Populate health_info table with random values
    for i in range(100):
        first_name = random.choice(first_names)  # Randomly select a first name
        last_name = random.choice(last_names)    # Randomly select a last name
        gender = random.choice(genders)          # Randomly select gender (True or False)
        age = random.choice(ages)                # Randomly select age from the predefined range
        weight = random.choice(weights)          # Randomly select weight from the list
        height = random.choice(heights)          # Randomly select height from the list
        health_history = random.choice(health_histories)  # Randomly select a health history

        # Encrypt gender and age before inserting into database
        encrypted_gender = cipher_suite.encrypt(str(gender).encode())  # Encrypt gender (True/False)
        encrypted_age = cipher_suite.encrypt(str(age).encode())        # Encrypt age (int)

         # Convert encrypted data to base64 for storage
        encoded_encrypted_gender = base64.b64encode(encrypted_gender).decode('utf-8')
        encoded_encrypted_age = base64.b64encode(encrypted_age).decode('utf-8')

        # Create a string representation of the data (excluding the ID)
        data_string = f"{first_name}{last_name}{weight}{height}{health_history}"

         # Generate SHA-256 checksum of the data
        data_hash = hashlib.sha256(data_string.encode('utf-8')).hexdigest()

        cursor.execute(
            "INSERT INTO health_info (first_name, last_name, gender, age, weight, height, health_history) VALUES (%s, %s, %s, %s, %s, %s, %s)",
            (first_name, last_name, encoded_encrypted_gender, encoded_encrypted_age, weight, height, health_history)
        )

    # Add users
    cursor.execute("INSERT INTO users_info (username, password_hash, role) VALUES (%s, %s, %s)",
                   ("admin", bcrypt.hashpw("admin123".encode(), bcrypt.gensalt()).decode(), "H"))
    cursor.execute("INSERT INTO users_info (username, password_hash, role) VALUES (%s, %s, %s)",
                   ("user", bcrypt.hashpw("user123".encode(), bcrypt.gensalt()).decode(), "R"))

    # Commit changes and close connection
    conn.commit()

except mysql.connector.Error as err:
    print(f"Error: {err}")
finally:
    if conn.is_connected():
        cursor.close()
        conn.close()	