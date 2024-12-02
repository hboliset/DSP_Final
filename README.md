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
3. Basic knowledge of SQL and Python.

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


----
Security Features Evaluation
1. User Authentication 
To ensure secure access to the system, we implemented a custom user authentication mechanism using username and password. The design avoids storing plain-text passwords by employing secure hashing techniques, as follows:

Username and Password Authentication:
Each user is required to authenticate themselves using a valid username and password combination before accessing the system. This ensures that only legitimate users are granted access.

Secure Password Storage:
The system uses the SHA-256 hashing algorithm to hash user passwords before storing them. The original password is never stored, ensuring enhanced security. During login, the password provided by the user is hashed again, and the resulting hash is compared with the stored hash for authentication.

Implementation Highlights:

The password hashing ensures that even if the authentication data is compromised, the original passwords remain undisclosed.
The solution does not rely on the database for password management but instead employs a standalone mechanism, maintaining full control over the authentication process.
   
