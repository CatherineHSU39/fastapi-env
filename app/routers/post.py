from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from schemas.post import PostCreate, PostUpdate, PostRead
from controllers import post
from database import get_db
from pydantic import PositiveInt

post_router = APIRouter()

@post_router.post('', response_model=PostRead)
def create_post(post_item: PostCreate, db: Session = Depends(get_db)):
	return post.create(db=db, post=post_item)

@post_router.get('/{post_id}', response_model=PostRead)
def update_post(post_id: PositiveInt, db: Session = Depends(get_db)):
	return post.read(db=db, post_id=post_id)

@post_router.put('/{post_id}', response_model=PostRead)
def update_post(post_item: PostUpdate, post_id: PositiveInt, db: Session = Depends(get_db)):
	return post.update(db=db, post_id=post_id, post=post_item)

@post_router.delete('/{post_id}')
def update_post(post_id: PositiveInt, db: Session = Depends(get_db)):
	return post.delete(db=db, post_id=post_id)