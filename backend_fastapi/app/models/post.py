from sqlalchemy import Column, String, Text, BigInteger, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from database import Base
from datetime import datetime, timedelta
from sqlalchemy.dialects import sqlite

BigIntegerType = BigInteger().with_variant(sqlite.INTEGER(), 'sqlite')

def now():
    return datetime.now()+timedelta(hours=8)

class Post(Base):
    __tablename__ = "posts"
    id = Column(BigIntegerType, primary_key=True, index=True)
    title = Column(String(length=100), index=True)
    content = Column(Text)
    poster = Column(BigIntegerType, ForeignKey("users.id", ondelete='CASCADE', onupdate='CASCADE'))
    created_at = Column(DateTime, default=now)
    updated_at = Column(DateTime, default=now, onupdate=now)

    user = relationship("User", back_populates="posts", uselist=False)
    tags = relationship("PostTag", back_populates="post")
    comments = relationship("Comment", back_populates="post")

class PostTag(Base):
    __tablename__ = "post_tags"
    id = Column(BigIntegerType, primary_key=True, index=True)
    tag = Column(String(length=20), index=True)
    post_id = Column(BigIntegerType, ForeignKey("posts.id", ondelete='CASCADE', onupdate='CASCADE'))
    created_at = Column(DateTime, default=now)

    post = relationship("Post", back_populates="tags", uselist=False)