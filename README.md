## Project Overview
This project is part of the **Data Security and Privacy (Fall 2024)** course. The goal is to design, implement, and evaluate a **secure database-as-a-service (DBaaS) system**. The system ensures data security while leveraging cloud services for storage and querying.

### Key Features
- Data encryption to protect sensitive healthcare information.
- Secure storage in a cloud-like environment using SQL databases.
- Implementation of security mechanisms to mitigate semi-trusted cloud risks.

---

## Project Setup

### Prerequisites
1. **GitHub Codespaces** or a local development environment.
2. **MySQL** database installed on the system.
3. Basic knowledge of SQL and Python (if applicable for encryption).

---

### Database Setup
1. Open the terminal in the project directory.
2. Start MySQL server:
   ```bash
   sudo service mysql start

Create the database and table using the setup.sql script:

mysql -u root -p < setup.sql

---

Table Schema
The database contains a single table with the following fields:

FirstName (VARCHAR): Patient's first name.
LastName (VARCHAR): Patient's last name.
Gender (BOOLEAN): Gender (0 = Female, 1 = Male).
Age (INT): Age in years.
Weight (FLOAT): Weight in kilograms.
Height (FLOAT): Height in meters.
HealthHistory (TEXT): Medical history.
   
