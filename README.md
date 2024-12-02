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

---
Basic Access Control Mechanism (5 pts)
To support access control for two distinct groups of users, Group H (high-privilege users) and Group R (restricted-access users), we developed a mechanism that enforces role-based access. The implemented system adheres to the following principles:

Group H Access:
Users in Group H have full privileges, including:

Access to all fields (e.g., first name, last name, and other attributes).
Permissions to query, view, and add new data items to the database.
Group R Access:
Users in Group R have restricted privileges:

They can query existing data items but are prohibited from viewing sensitive fields such as first name and last name.
They do not have permission to add new data items to the database.
Implementation Details:

When a user queries data, their group membership is checked. If the user belongs to Group R, fields like first name and last name are automatically excluded from the returned data.
Only users from Group H can execute data addition operations, enforcing stricter control over data modification.

----


   System Design and Security Considerations
The authentication and access control mechanisms are integrated seamlessly to ensure that users can only perform actions appropriate to their roles.
Hashing and role-based access control prevent unauthorized data access and ensure that sensitive information is protected from disclosure.
By implementing custom authentication and access control mechanisms, the system avoids reliance on external databases for critical security functions, reducing the attack surface and enhancing security.
