from pydantic import BaseModel, Field, PositiveInt, ConfigDict
from typing import Annotated, Optional
from datetime import datetime
from schemas.comment import CommentRead

class PostBase(BaseModel):
    title: Annotated[str, Field(max_length = 50)]
    content: str

class PostCreate(PostBase):
    tags: list[str] = []

class PostRead(PostBase):
    poster: PositiveInt
    id: PositiveInt
    created_at: datetime
    updated_at: datetime
    tags: list[str] = []
    comments: list[CommentRead] = []

    model_config = ConfigDict(
        from_attributes = True
    )

class PostUpdate(PostBase):
    tags: Optional[list[str]] = None

class PostSimple(BaseModel):
    title: str
    tags: list[str] = []
    id: PositiveInt

class PostSearchResponse(BaseModel):
    posts: list[PostSimple]