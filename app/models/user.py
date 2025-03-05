from sqlalchemy import Column, String, BigInteger, DateTime
from sqlalchemy.orm import relationship
from database import Base
from datetime import datetime, timedelta
from sqlalchemy.dialects import sqlite

BigIntegerType = BigInteger().with_variant(sqlite.INTEGER(), 'sqlite')

def now():
    return datetime.now()+timedelta(hours=8)

class User(Base):
    __tablename__ = "users"
    id = Column(BigIntegerType, primary_key=True, index=True)
    name = Column(String(length=100), index=True, nullable=False)
    created_at = Column(DateTime, default=now)
    updated_at = Column(DateTime, default=now, onupdate=now)

    user_authentication = relationship("UserAuthentication", back_populates="user", uselist=False)

# from .user_authentication import UserAuthentication
# UserAuthentication.user = relationship(User, primaryjoin=User.id == UserAuthentication.user_id)