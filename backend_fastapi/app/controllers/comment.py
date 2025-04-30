from fastapi import HTTPException
from sqlalchemy.orm import Session
from schemas.comment import CommentCreate, CommentUpdate
from models.comment import Comment, CommentHistory
from schemas.user import UserProfile
from common.role import *

def create(db: Session, comment: CommentCreate, post_id: int, user: UserProfile):
    if user.role == ANYMOUS:
        raise HTTPException(
            status_code=401,
            detail="You should login first."
        )

    db_comment = Comment(
        content = comment.content,
        reply_to = comment.reply_to,
        author = user.id,
        post_id = post_id
    )
    db.add(db_comment)
    db.commit()
    return db_comment

def read(db: Session, comment_id: int):
    db_comment = db.query(Comment).filter(Comment.id == comment_id).first()
    
    if db_comment == None:
        raise HTTPException(
            status_code=404,
            detail="Post not found."
        )
    
    return db_comment


def update(db: Session, comment_id: int, comment: CommentUpdate, user: UserProfile):
    db_comment = db.query(Comment).filter(Comment.id == comment_id).first()

    if db_comment == None:
        raise HTTPException(
            status_code=404,
            detail="Post not found."
        )

    if user.role == ANYMOUS:
        raise HTTPException(
            status_code=401,
            detail="You should login first."
        )
    if user.role == USER and user.id != db_comment.author:
        raise HTTPException(
            status_code=403,
            detail="You don't have permission to do that!"
        )
    
    db_comment_his = CommentHistory(
        content = db_comment.content,
        comment_id = comment_id,
        version = len(db_comment.history),
        created_at = db_comment.updated_at
    )
    db.add(db_comment_his)
    
    db_comment.content = comment.content

    db.commit()
    return db_comment

def delete(db: Session, comment_id: int, user: UserProfile):
    db_comment = db.query(Comment).filter(Comment.id == comment_id).first()

    if db_comment == None:
        raise HTTPException(
            status_code=404,
            detail="Post not found."
        )

    if user.role == ANYMOUS:
        raise HTTPException(
            status_code=401,
            detail="You should login first."
        )
    if user.role == USER and user.id != db_comment.author:
        raise HTTPException(
            status_code=403,
            detail="You don't have permission to do that!"
        )

    db.delete(db_comment)
    db.commit()
    return {"message": "Post deleted successfully"}