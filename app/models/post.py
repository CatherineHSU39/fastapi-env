from sqlalchemy import Column, String, Text, BigInteger, DateTime
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
    poster = Column(BigIntegerType)
    created_at = Column(DateTime, default=now)
    updated_at = Column(DateTime, default=now, onupdate=now)