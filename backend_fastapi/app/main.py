from fastapi import FastAPI, APIRouter, Depends
from fastapi.middleware.cors import CORSMiddleware
from routers.post import post_router
from routers.login import login_router
from routers.comment import comment_router
from models.user import User
from starlette.middleware.sessions import SessionMiddleware
from sqlalchemy.orm import Session
from database import get_db
from middlewares.auth import auth_middleware
from dotenv import load_dotenv
import os

load_dotenv()

app = FastAPI()

router = APIRouter()
router.include_router(
    post_router,
    prefix='/posts',
    tags=['posts'],
)
# router.include_router(
#     login_router
# )
router.include_router(
    comment_router,
    prefix='/comments',
    tags=['comments'],
)
app.include_router(router)

app.add_middleware(SessionMiddleware, secret_key=os.getenv('APP_SECRET'))

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.middleware("http")(auth_middleware)

@app.on_event("startup")
def on_startup():
    db = next(get_db())
    db_user = db.query(User).first()
    if db_user is None:
        db_user = User(**{"name":"admin","role":"admin"})
        db.add(db_user)
        db.commit()