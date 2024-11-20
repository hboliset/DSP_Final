import mysql.connector
import bcrypt
import random

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
conn = mysql.connector.connect(user='root', password='mysqlgit15', database='dsp_db')
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

    cursor.execute(
        "INSERT INTO health_info (first_name, last_name, gender, age, weight, height, health_history) VALUES (%s, %s, %s, %s, %s, %s, %s)",
        (first_name, last_name, gender, age, weight, height, health_history)
    )

# Add users
cursor.execute("INSERT INTO users_info (username, password_hash, role) VALUES (%s, %s, %s)",
               ("admin", bcrypt.hashpw("admin123".encode(), bcrypt.gensalt()).decode(), "H"))
cursor.execute("INSERT INTO users_info (username, password_hash, role) VALUES (%s, %s, %s)",
               ("user", bcrypt.hashpw("user123".encode(), bcrypt.gensalt()).decode(), "R"))

# Commit changes and close connection
conn.commit()
conn.close()
