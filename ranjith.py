# MySQL Interaction

import mysql.connector

# Connect to MySQL Database
def connect_to_database():
    try:
        connection = mysql.connector.connect(
            host="localhost",      # Change if using a remote server
            user="root",           # Your MySQL root user
            password="your_password",  
            database="dsp_db"      # Name of your database
        )
        print("Connection to MySQL established!")
        return connection
    except mysql.connector.Error as err:
        print(f"Error: {err}")
        return None

# Insert sample data into health_info table
def insert_data(connection):
    cursor = connection.cursor()
    query = """
    INSERT INTO health_info (first_name, last_name, gender, age, weight, height, health_history)
    VALUES (%s, %s, %s, %s, %s, %s, %s)
    """
    data = [
        ("John", "Doe", True, 30, 75.5, 1.8, "No significant medical history."),
        ("Jane", "Smith", False, 28, 60.2, 1.65, "Asthma since childhood."),
    ]
    cursor.executemany(query, data)
    connection.commit()
    print(f"{cursor.rowcount} records inserted.")

# Fetch and display data from health_info table
def fetch_data(connection):
    cursor = connection.cursor()
    query = "SELECT * FROM health_info"
    cursor.execute(query)
    results = cursor.fetchall()
    print("Fetched Data:")
    for row in results:
        print(row)

# Main Execution
if __name__ == "__main__":
    db_connection = connect_to_database()
    if db_connection:
        insert_data(db_connection)
        fetch_data(db_connection)
        db_connection.close()
