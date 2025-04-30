from unittest.mock import patch, AsyncMock, Mock
from models.user import User
from models.user_authentication import UserAuthentication
from tests.conftest import TestingSessionLocal

def test_login_via_github_redirect(client):
    response = client.get("/login/github", follow_redirects=False)
    assert response.status_code == 302
    assert "location" in response.headers
    assert "https://github.com/login/oauth/authorize?response_type=code&client_id=Ov23liayNm0GTmFQWwd5&redirect_uri=http%3A%2F%2Ftestserver%2Fauth%2Fgithub" in response.headers["location"]

def test_unsigned_user_github_callback(client):
    with patch('controllers.login.oauth.github.authorize_access_token') as mock_authorize_access_token:
        mock_authorize_access_token.return_value = {
            'access_token': 'fake_access_token',
            'token_type': 'bearer'
        }

        with patch('controllers.login.oauth.github.get', new_callable=AsyncMock) as mock_get_user_profile:
            mock_response = Mock()
            mock_response.json.return_value = {
                'id': '1',
                'login': 'test'
            }
            mock_get_user_profile.return_value = mock_response

            response = client.get('/auth/github?code=test_code&status=test_status')

            assert response.status_code == 200
            assert all(item in response.json()["user"] for item in {"id": 1, "name": "test"})

def test_signed_user_github_callback(client):
    with patch('controllers.login.oauth.github.authorize_access_token') as mock_authorize_access_token:
        mock_authorize_access_token.return_value = {
            'access_token': 'fake_access_token',
            'token_type': 'bearer'
        }

        with patch('controllers.login.oauth.github.get', new_callable=AsyncMock) as mock_get_user_profile:
            mock_response = Mock()
            mock_response.json.return_value = {
                'id': '1',
                'login': 'test'
            }
            mock_get_user_profile.return_value = mock_response


            session = TestingSessionLocal()
            db_user = User(**{"name": "a"})
            session.add(db_user)
            session.commit()
            db_user_auth = UserAuthentication(**{"provider": "github", "provider_user_id": "1", "user_id": 1})
            session.add(db_user_auth)
            session.commit()

            response = client.get('/auth/github')

            assert response.status_code == 200
            assert all(item in response.json()["user"] for item in {"id": 1, "name": "a"})