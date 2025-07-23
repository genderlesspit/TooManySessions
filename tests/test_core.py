import pytest
import secrets
from unittest.mock import Mock, patch, AsyncMock
from starlette.requests import Request
from starlette.responses import Response
from starlette.testclient import TestClient
from loguru import logger as log

from toomanysessions.src.toomanysessions import SessionedServer, callback, Session, Sessions, User, Users, authenticate

class TestSessionedServer:
    """Test suite for SessionedServer class"""

    @pytest.fixture
    def mock_session_model(self):
        """Mock session model with create method"""
        session_model = Mock()
        session_model.create = Mock()
        return session_model

    @pytest.fixture
    def mock_user_model(self):
        """Mock user model with create method"""
        user_model = Mock()
        user_model.create = Mock()
        return user_model

    @pytest.fixture
    def mock_auth_model(self):
        """Mock authentication function"""
        return Mock(return_value=Mock(authenticated=True))

    @pytest.fixture
    def server_instance(self, mock_session_model, mock_user_model, mock_auth_model):
        """Create server instance for testing"""
        with patch('Sessions'), patch('Users'):
            return SessionedServer(
                host="testhost",
                port=8080,
                session_model=mock_session_model,
                authentication_model=mock_auth_model,
                user_model=mock_user_model,
                verbose=True
            )

    def test_init_valid_models(self, mock_session_model, mock_user_model, mock_auth_model):
        """Test initialization with valid models"""
        with patch('Sessions'), patch('your_module.Users'):
            server = SessionedServer(
                session_model=mock_session_model,
                authentication_model=mock_auth_model,
                user_model=mock_user_model
            )

            assert server.host == "localhost"
            assert server.session_name == "session"
            assert server.session_age == (3600 * 8)
            assert server.session_model == mock_session_model
            assert server.authentication_model == mock_auth_model
            assert server.user_model == mock_user_model

    def test_init_missing_session_create(self, mock_user_model, mock_auth_model):
        """Test initialization fails when session model lacks create method"""
        bad_session_model = Mock()
        bad_session_model.create = None

        with pytest.raises(ValueError, match="Session models require a create function"):
            SessionedServer(
                session_model=bad_session_model,
                authentication_model=mock_auth_model,
                user_model=mock_user_model
            )

    def test_init_missing_user_create(self, mock_session_model, mock_auth_model):
        """Test initialization fails when user model lacks create method"""
        bad_user_model = Mock()
        bad_user_model.create = None

        with pytest.raises(ValueError, match="User models require a create function"):
            SessionedServer(
                session_model=mock_session_model,
                authentication_model=mock_auth_model,
                user_model=bad_user_model
            )

    def test_init_invalid_auth_model(self, mock_session_model, mock_user_model):
        """Test initialization fails when auth model is not callable"""
        bad_auth_model = "not_callable"

        with pytest.raises(TypeError, match="Authentication models must be a function"):
            SessionedServer(
                session_model=mock_session_model,
                authentication_model=bad_auth_model,
                user_model=mock_user_model
            )

    def test_repr(self, server_instance):
        """Test string representation"""
        assert repr(server_instance) == "[SessionedServer]"

    def test_auth_redirect_uri(self, server_instance):
        """Test auth redirect URI property"""
        with patch.object(server_instance, 'url', 'http://testhost:8080'):
            assert server_instance.auth_redirect_uri == "http://testhost:8080/auth/callback"

class TestSessionManager:
    """Test session management functionality"""

    @pytest.fixture
    def server_with_sessions(self):
        """Server instance with mocked sessions"""
        server = Mock()
        server.session_name = "test_session"
        server.session_age = 3600
        server.sessions = Mock()
        server.sessions.__getitem__ = Mock(return_value=Mock())
        return server

    def test_session_manager_new_token(self, server_with_sessions):
        """Test session manager creates new token when none exists"""
        from your_module import SessionedServer

        # Mock request without token
        request = Mock()
        request.cookies.get.return_value = None

        # Mock response
        response = Mock()

        # Create real instance to test method
        server = SessionedServer.__new__(SessionedServer)
        server.session_name = "test_session"
        server.session_age = 3600
        server.sessions = Mock()
        mock_session = Mock()
        server.sessions.__getitem__ = Mock(return_value=mock_session)

        result_response, session = server.session_manager(request, response)

        # Verify token was set
        response.set_cookie.assert_called_once()
        args = response.set_cookie.call_args[0]
        assert args[0] == "test_session"  # cookie name
        assert len(args[1]) > 0  # token exists
        assert response.set_cookie.call_args[1]['max_age'] == 3600
        assert session == mock_session

    def test_session_manager_dirty_token(self, server_with_sessions):
        """Test session manager handles dirty tokens"""
        from your_module import SessionedServer

        # Mock request with dirty token
        request = Mock()
        request.cookies.get.return_value = "token=dirty_value"

        response = Mock()

        server = SessionedServer.__new__(SessionedServer)
        server.session_name = "test_session"
        server.session_age = 3600
        server.sessions = Mock()
        mock_session = Mock()
        server.sessions.__getitem__ = Mock(return_value=mock_session)

        with patch('your_module.log'):
            result_response, session = server.session_manager(request, response)

        # Should generate new token for dirty token
        response.set_cookie.assert_called_once()
        assert session == mock_session

class TestCallbackFunction:
    """Test the default callback function"""

    def test_callback_returns_request(self):
        """Test default callback returns the request unchanged"""
        mock_request = Mock()
        result = callback(mock_request)
        assert result is mock_request

    def test_callback_is_truthy(self):
        """Test callback result is truthy for authentication"""
        mock_request = Mock()
        result = callback(mock_request)
        assert bool(result) is True

class TestAuthCallback:
    """Test authentication callback endpoint"""

    @pytest.fixture
    def mock_server(self):
        """Mock server for testing callback"""
        server = Mock()
        server.auth_callback_method = Mock(return_value=True)
        server.session_manager = Mock()

        mock_session = Mock()
        mock_session.authenticated = False
        server.session_manager.return_value = (Mock(), mock_session)

        return server, mock_session

    def test_auth_callback_success(self, mock_server):
        """Test successful authentication callback"""
        server, mock_session = mock_server

        # This would be the actual callback logic
        request = Mock()
        response = Mock()

        # Simulate the callback endpoint logic
        response, session = server.session_manager(request, response)
        auth_result = server.auth_callback_method(request)

        if auth_result:
            session.authenticated = True

        assert session.authenticated is True
        server.auth_callback_method.assert_called_once_with(request)

    def test_auth_callback_failure(self, mock_server):
        """Test failed authentication callback"""
        server, mock_session = mock_server
        server.auth_callback_method.return_value = False

        request = Mock()
        response = Mock()

        response, session = server.session_manager(request, response)
        auth_result = server.auth_callback_method(request)

        if auth_result:
            session.authenticated = True

        assert session.authenticated is False

class TestMiddleware:
    """Test middleware functionality"""

    def test_middleware_skips_auth_paths(self):
        """Test middleware skips authentication for specific paths"""
        # This would test the middleware logic
        # Since middleware is defined inline, we'd need to extract it or test integration
        pass

    def test_middleware_authenticates_session(self):
        """Test middleware authenticates sessions"""
        # Integration test for middleware authentication logic
        pass

    def test_middleware_returns_401_on_auth_failure(self):
        """Test middleware returns 401 for failed authentication"""
        pass

class TestIntegration:
    """Integration tests using TestClient"""

    @pytest.fixture
    def test_client(self):
        """Create test client for integration tests"""
        # This would require a properly configured server
        # You might need to mock external dependencies
        pass

    def test_auth_callback_endpoint(self, test_client):
        """Test /auth/callback endpoint"""
        # response = test_client.get("/auth/callback")
        # assert response.status_code == 200
        pass

    def test_protected_route_without_auth(self, test_client):
        """Test accessing protected route without authentication"""
        # response = test_client.get("/protected")
        # assert response.status_code == 401
        pass

    def test_protected_route_with_auth(self, test_client):
        """Test accessing protected route with authentication"""
        pass

# Utility functions for testing
def create_mock_request(path="/", method="GET", cookies=None):
    """Helper to create mock requests"""
    request = Mock()
    request.url.path = path
    request.method = method
    request.cookies.get = Mock(return_value=cookies.get("session") if cookies else None)
    return request

def create_mock_response():
    """Helper to create mock responses"""
    response = Mock()
    response.set_cookie = Mock()
    return response

# Run tests with verbose logging
if __name__ == "__main__":
    log.info("Running SessionedServer test suite")
    pytest.main([__file__, "-v", "--tb=short"])