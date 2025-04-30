from sqlalchemy import Column, Text, BigInteger, DateTime, ForeignKey, UniqueConstraint, Integer
from sqlalchemy.orm import relationship
from database import Base
from datetime import datetime, timedelta
from sqlalchemy.dialects import sqlite

BigIntegerType = BigInteger().with_variant(sqlite.INTEGER(), 'sqlite')

def now():
    return datetime.now()+timedelta(hours=8)

class Comment(Base):
    __tablename__ = "comments"
    id = Column(BigIntegerType, primary_key=True, index=True)
    content = Column(Text)
    reply_to = Column(BigIntegerType, ForeignKey("comments.id", ondelete="SET NULL", onupdate='CASCADE'))
    author = Column(BigIntegerType, ForeignKey("users.id", ondelete="SET NULL", onupdate='CASCADE'))
    post_id = Column(BigIntegerType, ForeignKey("posts.id", ondelete="SET NULL", onupdate='CASCADE'))
    created_at = Column(DateTime, default=now)
    updated_at = Column(DateTime, default=now, onupdate=now)

    post = relationship("Post", back_populates="comments", uselist=False)
    user = relationship("User", back_populates=None, uselist=False)
    history = relationship("CommentHistory", back_populates=None)

class CommentHistory(Base):
    __tablename__ = "comment_history"
    id = Column(BigIntegerType, primary_key=True, index=True)
    content = Column(Text)
    comment_id = Column(BigIntegerType, ForeignKey("comments.id", ondelete='CASCADE', onupdate='CASCADE'))
    version = Column(Integer)
    created_at = Column(DateTime, default=now)

    __table_args__ = (
        UniqueConstraint('version', 'comment_id', name='uq_version_comment_id'),
    )