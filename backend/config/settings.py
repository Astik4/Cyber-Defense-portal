import os
from dotenv import load_dotenv

# Load from .env file up two directories (since we're in backend/config)
dot_env_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../.env'))
load_dotenv(dot_env_path)

class Config:
    # Auth Config
    ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')
    ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'supershield')

    SECRET_KEY = os.environ.get('SECRET_KEY', 'cyber-defense-super-secret')
    DB_FILE = os.path.join(os.path.dirname(__file__), '../db/cybershield.db')
    DEBUG = True
    PORT = 5000
    
    # AI Config
    GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY', None)
    
    # Scanning Thresholds
    MAX_PACKETS_TO_KEEP = 50
    CPU_SPIKE_THRESHOLD = 80.0

settings = Config()
