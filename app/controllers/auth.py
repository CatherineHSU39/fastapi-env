from fastapi import Request, HTTPException
from schemas.user import UserProfile

def get_current_user(request: Request) -> UserProfile:
    if not hasattr(request.state, "user"):
        raise HTTPException(status_code=401, detail="Unauthorized")
    return request.state.user