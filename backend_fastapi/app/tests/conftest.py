from fastapi.testclient import TestClient
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import sys

sys.path.append('/code/app')

from main import app
from database import Base, get_db
from controllers.token import create_access_token
from common.role import OWNER

engine = create_engine("sqlite:///./tests/test.sqlite")
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

@pytest.fixture(scope="function")
def init_test_db():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)

def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture(scope="function")
def client(init_test_db):
    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)

    # Act as highest permission in default.
    fake_user_data = {"id": 1, "role": OWNER, "name": "test"}
    access_token = create_access_token(data=fake_user_data)
    client.headers.update({"Authorization": f"Bearer {access_token}"})

    yield client
    app.dependency_overrides.clear()