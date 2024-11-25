from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

db = SQLAlchemy()
csrf = CSRFProtect()


def create_app():
    app = Flask(__name__)

    # Add Secret Key and Database Configuration
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'Mthokozisi')  # Use environment variable or default fallback
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

    # Initialize extensions
    db.init_app(app)
    csrf.init_app(app)

    return app
