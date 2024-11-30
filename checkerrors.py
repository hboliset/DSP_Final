import os
from dotenv import load_dotenv


load_dotenv()
secret = os.getenv("JWT_SECRET")
if not secret:
    print("JWT_SECRET is not loaded from .env")
else:
    print("JWT_SECRET loaded successfully")
