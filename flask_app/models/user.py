from flask_app.config.mysqlcontroller import connectToMySQL
from flask_bcrypt import Bcrypt
from flask import flash
from flask_app import app
import re
bcrypt = Bcrypt(app)

LETTERS_REGEX = re.compile(r'^[a-zA-Z]+$')
PASSWORD_REGEX = re.compile(r'^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$')
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')

class User:
    def __init__(self, data):
        self.id = data['id']
        self.first_name = data['first_name']
        self.last_name = data['last_name']
        self.email = data['email']
        self.password = data['password']
        self.created_at = data['created_at']
        self.updated_at = data['updated_at']

    @classmethod
    def save(cls, data):
        query = "INSERT INTO users (first_name, last_name, email, password) VALUES (%(first_name)s, %(last_name)s, %(email)s, %(password)s)"
        return connectToMySQL('login_registration').query_db(query, data)

    @classmethod
    def get_all(cls, data):
        query = "SELECT * FROM users"
        results = connectToMySQL('login_registration').query_db(query, data)
        users = []
        for row in results:
            users.append( cls(row))
        return users

    @classmethod 
    def get_user_by_id(cls, data):
        query = "SELECT * FROM users WHERE id = %(id)s;"
        
        results = connectToMySQL('login_registration').query_db(query, data)

        if not results or len(results) == 0: 
            return False
        else:
            return cls(results[0])

    @classmethod
    def get_user_email(cls, data):
        query = "SELECT * FROM users WHERE email = %(email)s"
        results = connectToMySQL('login_registration').query_db(query, data)
        if len(results) == 0:
            return False
        else:
            return cls(results[0])

    @classmethod
    def check_email_in_db(cls, data):
        query = "SELECT * FROM users WHERE email = %(email)s"
        
        results = connectToMySQL('login_registration').query_db(query, data)
        return len(results) == 0


    @staticmethod
    def valid_registration(new_user):
        is_valid = True
        
        if len(new_user['first_name']) == 0:
            flash('First name required', 'first_name')
            is_valid = False
        
        elif len(new_user['first_name']) < 3:
            flash('First name must require at least 3 characters', 'first_name')
            is_valid = False
        
        elif not LETTERS_REGEX.match(new_user['first_name']):
            flash('First name must contain alphabetical characters only', 'first_name')
            is_valid = False

        if len(new_user['last_name']) == 0:
            flash('Last name required', 'last_name')
            is_valid = False
        
        elif len(new_user['last_name']) < 3:
            flash('Last name must contain at least 3 characters', 'last_name')
            is_valid = False
        
        elif not LETTERS_REGEX.match(new_user['last_name']):
            flash ('Last name must contain alphabetical characters only', 'last_name')
            is_valid = False
        
        if len(new_user['email']) == 0:
            flash('Email required', 'email')
            is_valid = False
        
        elif not EMAIL_REGEX.match(new_user['email']):
            flash('Invalid email format', 'email')
            is_valid = False
        
        elif not User.check_email_in_db(new_user):
            flash('Email already exists', 'email')
            is_valid = False
        
        if len(new_user['password']) == 0:
            flash('Password required', 'password')
            is_valid = False
        
        elif not PASSWORD_REGEX.match(new_user['password']):
            flash('Password minimum eight characters, at least one letter and one number', 'password')
            is_valid = False
        
        elif new_user['password'] != new_user['con_password']:
            flash('Confirm password does not match password', 'con_password')
            is_valid = False
        return is_valid


    @staticmethod
    def valid_login(login_user):
        user_db = User.get_user_email(login_user)
        if not user_db:
            flash("Invalid email/password", "email_login")
            return False
        
        elif not bcrypt.check_password_hash(user_db.password, login_user['password']):
            flash('The password you\'ve entered is incorrect', 'email_login')
            return False
        
        return user_db