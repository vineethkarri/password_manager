from flask import Flask, render_template, request, redirect, url_for
from sqlalchemy import create_engine, Column, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import base64
import random


from sqlalchemy.orm import declarative_base

Base = declarative_base()

# Define User model
class User(Base):
    __tablename__ = 'users'

    username = Column(String, primary_key=True)
    password = Column(String, nullable=False)

# Configure the database connection
DATABASE_URL = "sqlite:///user_data.db"  # Use your desired database URL
engine = create_engine(DATABASE_URL, echo=True)
Base.metadata.create_all(bind=engine)

# Create a session to interact with the database
Session = sessionmaker(bind=engine)
session = Session()

# Repository-like class for User model
class UserRepository:
    @staticmethod
    def save(user):
        session.add(user)
        session.commit()

    @staticmethod
    def find_by_username(username):
        user = session.query(User).filter_by(username=username).first()
        return user

# Service class for additional functionality
class UserService:
    @staticmethod
    def encrypt_password(password):
        # In a real-world scenario, use a secure encryption method
        return base64.b64encode(password.encode()).decode()

    @staticmethod
    def decrypt_password(encrypted_password):
        # In a real-world scenario, use the corresponding decryption method
        return base64.b64decode(encrypted_password).decode()

# Initialize Flask app
app = Flask(__name__)

# Default route for the root endpoint
@app.route("/", methods=["GET", "POST"])
def home():
    if request.method == "POST":
        login_type = request.form.get("login_type")
        if login_type == "user":
            return redirect(url_for("user_login"))
        elif login_type == "admin":
            return redirect(url_for("admin_login"))
    return render_template("index.html")

# Route for user login
@app.route("/user_login", methods=["GET", "POST"])
def user_login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        # Encrypt the password
        encrypted_password = UserService.encrypt_password(password)

        # Save user data to the database
        user = User(username=username, password=encrypted_password)
        UserRepository.save(user)

        return f"User {username} logged in and data saved!"

    return render_template("user_login.html")

# Route for admin login
@app.route("/admin_login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        admin_username = request.form.get("admin_username")
        admin_password = request.form.get("admin_password")

        # In a real-world scenario, implement secure admin authentication
        if admin_username == "admin" and admin_password == "admin123":
            # Fetch all user data from the database
            users = session.query(User).all()
            user_data = [{'username': user.username,
                           'encrypted_password': user.password,
                           'decrypted_password': UserService.decrypt_password(user.password)} for user in users]

            return render_template("admin_login.html", user_data=user_data)

    return render_template("admin_login.html")

if __name__ == "__main__":
    app.run(debug=True)
