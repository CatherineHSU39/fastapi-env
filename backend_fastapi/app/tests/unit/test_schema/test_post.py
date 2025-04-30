from schemas.post import PostCreate
import pytest
from pydantic import ValidationError

def test_create():
    # Normal.
    PostCreate(**{"title":"a","content":"b"})

    # Missing some field.
    with pytest.raises(ValidationError):
        PostCreate(**{"title":"a"})
    with pytest.raises(ValidationError):
        PostCreate(**{"content":"b"})

    # More than 50 characters.
    with pytest.raises(ValidationError):
        PostCreate(**{"title":"12345678901234567890123456789012345678901234567890x", "content":"b"})