
Introduction
The User and Role Management System is a Flask-based REST API application that allows for managing users and their associated roles. The application provides CRUD operations for users and roles, user authentication, access control through roles, and additional features like bulk user updates and search functionalities. It enables administrators to manage user roles with different access levels to various modules of the system.

Features
User Management: Create, read, update, and delete users with basic details like name, email, and password.
Role Management: Create, update, and delete roles, along with managing a list of access modules that the role can control.
Authentication: Sign up new users and login using JWT-based authentication.
Access Control: Manage and check which modules a user has access to based on their assigned role.
Bulk User Updates: Update multiple users simultaneously with either the same data or different data.
Search: Search users based on their first name, last name, or email.
Module Access Management: Add or remove access to specific modules for any role.
Database-backed: Uses SQLite for persistence.
Python Version
The project is built with Python 3.7+. Below are the main libraries and dependencies required:

Dependencies
Flask: The micro web framework used to build the APIs.
Flask-SQLAlchemy: For ORM (Object-Relational Mapping) and database management.
Flask-Marshmallow: For object serialization and deserialization.
Flask-JWT-Extended: For managing JWT (JSON Web Token) based authentication.
Werkzeug: For password hashing and security.