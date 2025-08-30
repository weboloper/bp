# import sys
# import os

# # Add the backend directory to the Python path
# sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

# # Set the Django settings module (update if you use a different one)
# os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')

# # Import the WSGI application
# from config.wsgi import application

import sys
import os

# Define backend directory
backend_dir = os.path.join(os.path.dirname(__file__), 'backend')

# Change working directory so settings.py sees .env.dev inside backend
os.chdir(backend_dir)

# Add backend to Python path
sys.path.insert(0, backend_dir)

# Set Django settings module
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')

# Import WSGI application
from config.wsgi import application