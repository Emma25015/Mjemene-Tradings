import os
from dotenv import load_dotenv

load_dotenv()  # Load environment variables from a .env file

MAIL_SERVER = 'smtp.gmail.com'
MAIL_PORT = 587
MAIL_USE_TLS = True
MAIL_USERNAME = os.getenv('MAIL_USERNAME')
MAIL_PASSWORD = os.getenv('MAIL_PASSWORD')
MAIL_DEFAULT_SENDER = 'mjemenetradings.com'

SECRET_KEY = os.getenv('SECRET_KEY')
