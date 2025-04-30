from pydantic import BaseModel, PositiveInt, ConfigDict
from typing import Optional
from datetime import datetime

class CommentBase(BaseModel):
    content: str

class CommentCreate(CommentBase):
    reply_to: Optional[PositiveInt] = None

class CommentRead(CommentBase):
    id: PositiveInt
    reply_to: Optional[PositiveInt] = None
    author: PositiveInt
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(
        from_attributes = True
    )

class CommentUpdate(CommentBase):
    pass

class CommentHistoryBase(CommentBase):
    version: int
    created_at: datetime

    model_config = ConfigDict(
        from_attributes = True
    )

class CommentWithHistoryRead(CommentRead):
    history: list[CommentHistoryBase]