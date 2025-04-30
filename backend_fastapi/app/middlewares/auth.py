from fastapi import Request
from fastapi.responses import JSONResponse
from jose import JWTError, jwt
from dotenv import load_dotenv
import os
from schemas.user import UserProfile

load_dotenv()

SECRET_KEY = os.getenv("JWT_SECRET")
ALGORITHM = "HS256"

async def auth_middleware(request: Request, call_next):

    # Disable auth for simple setup.
    user = UserProfile(
            id = 1,
            name = "admin",
            role = "admin"
        )
    request.state.user = user
    return await call_next(request)


    token = request.headers.get("Authorization")
    if token is None:
        user = UserProfile(
            id = 2147483647,
            name = "anymous",
            role = "anymous"
        )
    else:
        try:
            token = token.split('Bearer ')[1]
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            user = UserProfile(
                id = payload.get("id"),
                name = payload.get("name"),
                role = payload.get("role")
            )
        except JWTError:
            return JSONResponse(status_code=401, content={"detail": "Invalid token"})
    
    request.state.user = user
    return await call_next(request)