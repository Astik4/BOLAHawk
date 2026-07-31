import os
from dotenv import load_dotenv

# Find the directory containing this config.py, and look for .env in the backend folder
backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
env_path = os.path.join(backend_dir, '.env')

load_dotenv(dotenv_path=env_path)

TARGET_API_URL = os.getenv("TARGET_API_URL", "http://127.0.0.1:5000").rstrip('/')
USERS_CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_users.json")
