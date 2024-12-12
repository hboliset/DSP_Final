import os
import mysql.connector
from dotenv import load_dotenv

# Load environment variables
load_dotenv()


def get_db():
    user = os.getenv("DB_USER")
    password = os.getenv("DB_PASSWORD")
    database = os.getenv("DB_NAME")

    if not user or not password or not database:
        raise ValueError("Database credentials are missing in environment variables")

    # Open a connection to the database
    db = mysql.connector.connect(
        user=user,
        password=password,
        database=database,
    )
    return db


def view_data_users():
    # Connect to the database
    db = get_db()
    cursor = db.cursor(dictionary=True)

    # Execute a query to fetch data
    cursor.execute("SELECT * FROM users_info")  # Replace with your table name
    data = cursor.fetchall()

    # Print the data
    for row in data:
        print(row)

    # Close the connection
    cursor.close()
    db.close()

def view_data_patients():
    # Connect to the database
    db = get_db()
    cursor = db.cursor(dictionary=True)

    # Execute a query to fetch data
    cursor.execute("SELECT * FROM health_info")  # Replace with your table name
    data = cursor.fetchall()

    # Print the data
    for row in data:
        print(row)

    # Close the connection
    cursor.close()
    db.close()


if __name__ == "__main__":
    view_data_users()
    #view_data_patients()
