from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from schemas.comment import CommentRead, CommentCreate, CommentUpdate, CommentWithHistoryRead
from schemas.user import UserProfile
from controllers import comment
from controllers.auth import get_current_user
from database import get_db
from pydantic import PositiveInt

comment_router = APIRouter()

@comment_router.post('', response_model=CommentRead)
def create_comment(post_id: PositiveInt, comment_item: CommentCreate, db: Session = Depends(get_db), user: UserProfile = Depends(get_current_user)):
	return comment.create(db=db, comment=comment_item, post_id=post_id, user=user)

@comment_router.get('/{comment_id}', response_model=CommentWithHistoryRead)
def get_comment(comment_id: PositiveInt, db: Session = Depends(get_db)):
	return comment.read(db=db, comment_id=comment_id)

@comment_router.put('/{comment_id}', response_model=CommentRead)
def update_comment(comment_item: CommentUpdate, comment_id: PositiveInt, db: Session = Depends(get_db), user: UserProfile = Depends(get_current_user)):
	return comment.update(db=db, comment_id=comment_id, comment=comment_item, user=user)

@comment_router.delete('/{comment_id}')
def delete_comment(comment_id: PositiveInt, db: Session = Depends(get_db), user: UserProfile = Depends(get_current_user)):
	return comment.delete(db=db, comment_id=comment_id, user=user)