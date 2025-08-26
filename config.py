# Configuration settings for the restaurant system
import os

SECRET_KEY = os.environ.get('SECRET_KEY') or os.urandom(24)
SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///restaurant.db'
SQLALCHEMY_TRACK_MODIFICATIONS = False