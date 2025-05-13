import sys
import os
import secrets

path = '/home/yourusername/Election'
if path not in sys.path:
    sys.path.insert(0, path)

os.environ['FLASK_ENV'] = 'production'  
os.environ['FLASK_DEBUG'] = '0'      

if 'SECRET_KEY' not in os.environ:
    os.environ['SECRET_KEY'] = secrets.token_hex(32)

from app import app as application

if __name__ == '__main__':
    application.run() 