from unittest.mock import Mock, patch

import httpx
import pytest

from nac_collector.controller.ndfc import CiscoClientNDFC

pytestmark = pytest.mark.unit


@pytest.fixture
def ndfc_client():
    """NDFC client with standard test parameters."""
    return CiscoClientNDFC(
        username="admin",
        password="admin_pass",
        base_url="https://ndfc.example.com",
        max_retries=3,
        retry_after=1,
        timeout=5,
        ssl_verify=False,
        fabric_name="test-fabric",
    )


@pytest.fixture
def ndfc_client_no_creds():
    """NDFC client without credentials."""
    return CiscoClientNDFC(
        username="",
        password="",
        base_url="https://ndfc.example.com",
        max_retries=3,
        retry_after=1,
        timeout=5,
        ssl_verify=False,
        fabric_name="test-fabric",
    )


@pytest.fixture
def ndfc_client_custom_domain():
    """NDFC client configured with a non-default authentication domain."""
    return CiscoClientNDFC(
        username="admin",
        password="admin_pass",
        base_url="https://ndfc.example.com",
        max_retries=3,
        retry_after=1,
        timeout=5,
        ssl_verify=False,
        fabric_name="test-fabric",
        domain="ISE",
    )


class TestAuthSuccess:
    """Tests for successful authentication scenarios."""

    def test_authenticate_success_with_token_key(self, ndfc_client):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"token": "my-jwt-token-123"}
        mock_response.headers = {}

        with patch.object(httpx.Client, "post", return_value=mock_response):
            result = ndfc_client.authenticate()

        assert result is True
        assert ndfc_client.client is not None
        assert "Bearer my-jwt-token-123" in ndfc_client.client.headers["Authorization"]

    def test_authenticate_success_with_jwt_token_key(self, ndfc_client):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"Jwt_Token": "jwt-token-value"}
        mock_response.headers = {}

        with patch.object(httpx.Client, "post", return_value=mock_response):
            result = ndfc_client.authenticate()

        assert result is True
        assert "Bearer jwt-token-value" in ndfc_client.client.headers["Authorization"]

    def test_authenticate_success_with_access_token_key(self, ndfc_client):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"access_token": "access-tok"}
        mock_response.headers = {}

        with patch.object(httpx.Client, "post", return_value=mock_response):
            result = ndfc_client.authenticate()

        assert result is True
        assert "Bearer access-tok" in ndfc_client.client.headers["Authorization"]

    def test_authenticate_success_with_jwttoken_key(self, ndfc_client):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"jwttoken": "jwt-lower"}
        mock_response.headers = {}

        with patch.object(httpx.Client, "post", return_value=mock_response):
            result = ndfc_client.authenticate()

        assert result is True
        assert "Bearer jwt-lower" in ndfc_client.client.headers["Authorization"]

    def test_authenticate_sets_content_type_headers(self, ndfc_client):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"token": "tok"}
        mock_response.headers = {}

        with patch.object(httpx.Client, "post", return_value=mock_response):
            ndfc_client.authenticate()

        assert ndfc_client.client.headers["Content-Type"] == "application/json"
        assert ndfc_client.client.headers["Accept"] == "application/json"

    def test_authenticate_extracts_auth_cookie(self, ndfc_client):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"token": "tok"}
        mock_response.headers = {
            "Set-Cookie": "AuthCookie=abc123def456; Path=/; HttpOnly"
        }

        with patch.object(httpx.Client, "post", return_value=mock_response):
            result = ndfc_client.authenticate()

        assert result is True
        assert ndfc_client.client.cookies.get("AuthCookie") == "abc123def456"

    def test_authenticate_posts_to_login_endpoint(self, ndfc_client):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"token": "tok"}
        mock_response.headers = {}

        with patch.object(
            httpx.Client, "post", return_value=mock_response
        ) as mock_post:
            ndfc_client.authenticate()

        mock_post.assert_called_once_with(
            "https://ndfc.example.com/login",
            json={
                "userName": "admin",
                "userPasswd": "admin_pass",
                "domain": "local",
            },
        )

    def test_authenticate_includes_default_domain_when_not_specified(self, ndfc_client):
        """Domain should default to 'local' and always be sent in the login payload."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"token": "tok"}
        mock_response.headers = {}

        with patch.object(
            httpx.Client, "post", return_value=mock_response
        ) as mock_post:
            ndfc_client.authenticate()

        _, kwargs = mock_post.call_args
        assert kwargs["json"]["domain"] == "local"

    def test_authenticate_uses_camelcase_credential_keys(self, ndfc_client):
        """ND's shared /login endpoint only honors 'domain' when the credential
        keys are userName/userPasswd (camelCase) -- lowercase username/password
        keys cause ND to silently ignore 'domain' and fall back to local-domain
        auth semantics. Verified against a live ND 4.2 instance."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"token": "tok"}
        mock_response.headers = {}

        with patch.object(
            httpx.Client, "post", return_value=mock_response
        ) as mock_post:
            ndfc_client.authenticate()

        _, kwargs = mock_post.call_args
        sent_json = kwargs["json"]
        assert "userName" in sent_json
        assert "userPasswd" in sent_json
        assert "username" not in sent_json
        assert "password" not in sent_json

    def test_authenticate_includes_custom_domain_in_login_payload(
        self, ndfc_client_custom_domain
    ):
        """A non-default domain (e.g. a remote AAA realm) must be sent to /login."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"token": "tok"}
        mock_response.headers = {}

        with patch.object(
            httpx.Client, "post", return_value=mock_response
        ) as mock_post:
            result = ndfc_client_custom_domain.authenticate()

        assert result is True
        mock_post.assert_called_once_with(
            "https://ndfc.example.com/login",
            json={
                "userName": "admin",
                "userPasswd": "admin_pass",
                "domain": "ISE",
            },
        )


class TestAuthFailure:
    """Tests for authentication failure scenarios."""

    def test_authenticate_fails_without_username(self, ndfc_client_no_creds):
        result = ndfc_client_no_creds.authenticate()

        assert result is False
        assert ndfc_client_no_creds.client is None

    def test_authenticate_fails_without_fabric_name(self, ndfc_client):
        ndfc_client.fabric_name = None

        result = ndfc_client.authenticate()

        assert result is False
        assert ndfc_client.client is None

    def test_authenticate_fails_on_non_200_status(self, ndfc_client):
        mock_response = Mock()
        mock_response.status_code = 401
        mock_response.text = "Unauthorized"

        with patch.object(httpx.Client, "post", return_value=mock_response):
            result = ndfc_client.authenticate()

        assert result is False

    def test_authenticate_fails_when_no_token_in_response(self, ndfc_client):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"message": "success", "user": "admin"}
        mock_response.headers = {}

        with patch.object(httpx.Client, "post", return_value=mock_response):
            result = ndfc_client.authenticate()

        assert result is False

    def test_authenticate_fails_on_connection_error(self, ndfc_client):
        with patch.object(
            httpx.Client, "post", side_effect=httpx.ConnectError("Connection refused")
        ):
            result = ndfc_client.authenticate()

        assert result is False

    def test_authenticate_fails_on_timeout(self, ndfc_client):
        with patch.object(
            httpx.Client, "post", side_effect=httpx.TimeoutException("Timeout")
        ):
            result = ndfc_client.authenticate()

        assert result is False

    def test_authenticate_fails_on_server_error(self, ndfc_client):
        mock_response = Mock()
        mock_response.status_code = 500
        mock_response.text = "Internal Server Error"

        with patch.object(httpx.Client, "post", return_value=mock_response):
            result = ndfc_client.authenticate()

        assert result is False
