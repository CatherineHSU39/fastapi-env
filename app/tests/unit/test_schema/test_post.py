from schemas.post import PostCreate
import pytest
from pydantic import ValidationError

def test_create():
    # Normal.
    PostCreate(**{"title":"a","content":"b","poster":1})

    # Missing some field.
    with pytest.raises(ValidationError):
        PostCreate(**{"title":"a", "content":"b"})
    with pytest.raises(ValidationError):
        PostCreate(**{"poster":1, "content":"b"})
    with pytest.raises(ValidationError):
        PostCreate(**{"title":"a", "poster":1})

    # More than 50 characters.
    with pytest.raises(ValidationError):
        PostCreate(**{"title":"12345678901234567890123456789012345678901234567890x", "content":"b", "poster":1})

    # poster <= 0.
    with pytest.raises(ValidationError):
        PostCreate(**{"title":"a", "content":"b", "poster":0})