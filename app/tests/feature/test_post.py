from models.post import Post
from tests.conftest import TestingSessionLocal

def test_create(client):
    # Normal create.
    response = client.post("/posts", json={"title": "string", "content": "string", "poster": 1})
    assert response.status_code == 200
    with TestingSessionLocal() as session:
        post = session.query(Post).filter(Post.id == 1).first()
        assert post is not None
        assert post.title == "string"
        assert post.content == "string"
        assert post.poster == 1

    # Validation failed.
    response = client.post("/posts", json={"title": "string", "content": "string", "poster": "abc"})
    assert response.status_code == 422


def test_read(client):
    # No data.
    response = client.get("/posts/1")
    assert response.status_code == 404

    # Create data.
    session = TestingSessionLocal()
    db_post = Post(**{"title": "a", "content": "b", "poster": 1})
    session.add(db_post)
    session.commit()

    # Normal read.
    response = client.get("/posts/" + str(db_post.id))
    assert response.status_code == 200
    assert all(item in response.json() for item in {"title": "a", "content": "b", "poster": 1})

def test_update(client):
    # No data.
    response = client.put("/posts/1", json={"title":"123", "content":"abc"})
    assert response.status_code == 404

    # Create data.
    session = TestingSessionLocal()
    db_post = Post(**{"title": "a", "content": "b", "poster": 1})
    session.add(db_post)
    session.commit()

    # Validation failed.
    response = client.put("/posts/"+ str(db_post.id), json={"title":"123"})
    assert response.status_code == 422

    # Normal update.
    response = client.put("/posts/"+ str(db_post.id), json={"title":"abc", "content":"123"})
    assert response.status_code == 200
    assert all(item in response.json() for item in {"title": "abc", "content": "123", "poster": 1})

def test_delete(client):
    # No data.
    response = client.delete("/posts/1")
    assert response.status_code == 404

    # Create data.
    session = TestingSessionLocal()
    db_post = Post(**{"title": "a", "content": "b", "poster": 1})
    session.add(db_post)
    session.commit()
    
    # Normal delete.
    response = client.delete("/posts/" + str(db_post.id))
    assert response.status_code == 200
    
    # Check database deleted.
    db_post = session.query(Post).filter(Post.id == db_post.id).first()
    assert db_post == None