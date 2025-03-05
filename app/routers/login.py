from fastapi import APIRouter, Request, Depends
from fastapi.security import OAuth2AuthorizationCodeBearer
from sqlalchemy.orm import Session
from controllers import login
from controllers.auth import get_current_user
from database import get_db
from schemas.user import UserWithToken

login_router = APIRouter()
oauth2_scheme = OAuth2AuthorizationCodeBearer(
    authorizationUrl="https://github.com/login/oauth/authorize",
    tokenUrl="https://github.com/login/oauth/access_token"
)

@login_router.get('/login/github')
async def login_via_github(request: Request):
    return await login.login_via_github(request)

@login_router.get('/auth/github', name='github_login_callback', response_model=UserWithToken)
async def auth_github(request: Request, db: Session = Depends(get_db)):
    return await login.auth_github(request, db)

@login_router.get('/check-user')
async def check_user(user = Depends(get_current_user)):
    return user