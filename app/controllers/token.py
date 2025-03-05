from datetime import datetime, timedelta
from fastapi import Depends
from jose import jwt
from dotenv import load_dotenv
import os
from fastapi.security import OAuth2AuthorizationCodeBearer

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

def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("name")

        return username
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
oauth2_scheme = OAuth2AuthorizationCodeBearer(
    authorizationUrl="https://github.com/login/oauth/authorize",
    tokenUrl="https://github.com/login/oauth/access_token"
)

def check_user(token: str = Depends(oauth2_scheme)):
    return verify_token(token)