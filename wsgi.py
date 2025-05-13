import sys
import os
import secrets

# Add your project directory to the sys.path
path = '/home/yourusername/Election'
if path not in sys.path:
    sys.path.insert(0, path)

# Set production environment variables
os.environ['FLASK_ENV'] = 'production'  # Set production mode
os.environ['FLASK_DEBUG'] = '0'         # Ensure debug is off

# Generate a secret key if not set
if 'SECRET_KEY' not in os.environ:
    os.environ['SECRET_KEY'] = secrets.token_hex(32)

# Import your app from app.py
from app import app as application

# This is needed for PythonAnywhere
if __name__ == '__main__':
    application.run() 