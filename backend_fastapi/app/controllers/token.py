from datetime import datetime, timedelta
from jose import jwt
from dotenv import load_dotenv
import os

load_dotenv()

SECRET_KEY = os.getenv("JWT_SECRET")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1440

def create_access_token(data: dict, expire_minutes: int= ACCESS_TOKEN_EXPIRE_MINUTES):
    to_encode = data.copy()
    for key, value in to_encode.items():
        if isinstance(value, datetime):
            to_encode[key] = value.isoformat()

    expire = datetime.now() + timedelta(minutes=expire_minutes)
    to_encode.update({"exp": expire, "sub": str(to_encode["id"])})

    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

    return encoded_jwt