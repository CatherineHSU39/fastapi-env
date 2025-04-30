from fastapi import HTTPException
from sqlalchemy.orm import Session
from schemas.post import PostCreate, PostUpdate, PostRead
from schemas.user import UserProfile
from models.post import Post, PostTag
from common.role import *

def transfer_post(db_post: Post) -> PostRead:
    db_tags = db_post.tags
    db_post.tags = []
    return_post = PostRead.model_validate(db_post)
    return_post.tags = [tag.tag for tag in db_tags]

    return return_post

def create(db: Session, post: PostCreate, user: UserProfile):
    if user.role == ANYMOUS:
        raise HTTPException(
            status_code=401,
            detail="You should login first."
        )

    db_post = Post(
        title=post.title,
        content=post.content,
        poster=user.id,
        tags= [PostTag(tag=tag) for tag in post.tags]
    )
    db.add(db_post)
    db.commit()
    return transfer_post(db_post)

def read(db: Session, post_id: int):
    db_post = db.query(Post).filter(Post.id == post_id).first()
    
    if db_post == None:
        raise HTTPException(
            status_code=404,
            detail="Post not found."
        )
    
    return transfer_post(db_post)

def update(db: Session, post_id: int, post: PostUpdate, user: UserProfile):
    db_post = db.query(Post).filter(Post.id == post_id).first()

    if db_post == None:
        raise HTTPException(
            status_code=404,
            detail="Post not found."
        )

    if user.role == ANYMOUS:
        raise HTTPException(
            status_code=401,
            detail="You should login first."
        )
    if user.role == USER and user.id != db_post.poster:
        raise HTTPException(
            status_code=403,
            detail="You don't have permission to do that!"
        )
    
    post_data = post.model_dump(exclude_unset=True)
    post_data.pop('tags', [])
    for key, value in post_data.items():
        setattr(db_post, key, value)

    if post.tags is not None:
        db_post.tags= [PostTag(tag=tag) for tag in post.tags]

    db.commit()
    return transfer_post(db_post)

def delete(db: Session, post_id: int, user: UserProfile):
    db_post = db.query(Post).filter(Post.id == post_id).first()

    if db_post == None:
        raise HTTPException(
            status_code=404,
            detail="Post not found."
        )

    if user.role == ANYMOUS:
        raise HTTPException(
            status_code=401,
            detail="You should login first."
        )
    if user.role == USER and user.id != db_post.poster:
        raise HTTPException(
            status_code=403,
            detail="You don't have permission to do that!"
        )

    db.delete(db_post)
    db.commit()
    return {"message": "Post deleted successfully"}

def search(db: Session, title: str, tags: list[str]):
    db_posts = db.query(Post)

    if title is not None:
        db_posts = db_posts.filter(Post.title.like(title))
    if tags is not None:
        db_posts = db_posts.join(Post.tags).filter(PostTag.tag.in_(tags))

    return {"posts": [transfer_post(db_post) for db_post in db_posts.all()]}