# Flask Network Tool

A Flask-based web application for managing users, authentication, and network-related functionality. Features include user registration, login, roles, and database migrations.

## Table of Contents
1. [Introduction](#introduction)
2. [Features](#features)
3. [Project Structure](#project-structure)
4. [Installation](#installation)
5. [Usage](#usage)
6. [Configuration](#configuration)
7. [Troubleshooting](#troubleshooting)
8. [Contributors](#contributors)
9. [License](#license)

## Introduction

The **Flask Network Tool** is a web application built using the Flask framework. It provides user management features like registration, login, roles, and permissions. The app uses SQLite as the default database and includes Flask-Migrate for easy database migrations.

## Features

- User Registration and Login
- User Roles and Permissions
- Profile Management
- SQLAlchemy ORM for Database Handling
- Flask-Migrate for Database Migrations
- SQLite as the Default Database

## Project Structure

```plaintext
/project_root
│
├── /instance                  # Contains the SQLite database
│   └── users.db
├── /templates                 # HTML templates for the app
│   ├── about.html
│   ├── dashboard.html
│   ├── index.html
│   ├── login.html
│   └── register.html
├── app.py                     # Main application file
├── models.py                  # Database models
├── /migrations                 # Auto-generated Flask-Migrate files
└── /static                    # Static files like CSS, JS

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/flask-network-tool.git
cd flask-network-tool


### 2. Create a Virtual Environment
    python -m venv venv

### 3.Activate the Virtual Environment
    ##Windows:

        bash
        Copy code
        .venv\Scripts\activate

    ##Linux/Mac:

        bash
        Copy code
        source .venv/bin/activate

### 4. Install Dependencies

    pip install -r requirements.txt

### 5. Initialize the Database

    flask db init
    flask db migrate -m "Initial migration"
    flask db upgrade

### 6. Run

    