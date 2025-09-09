from unittest.mock import MagicMock, patch

import httpx
import pytest

from nac_collector.device.ios_xe import CiscoClientIOSXE

pytestmark = pytest.mark.unit


@pytest.fixture
def sample_devices():
    """Sample device data for testing."""
    return [
        {
            "name": "Switch1",
            "url": "https://switch1.example.com",
            "username": "switch_user",
            "password": "switch_pass",
            "protocol": "restconf",
        },
        {
            "name": "Switch2",
            "url": "https://switch2.example.com",
        },
    ]


@pytest.fixture
def ios_xe_client(sample_devices):
    """Create a CiscoClientIOSXE instance for testing."""
    return CiscoClientIOSXE(
        devices=sample_devices,
        default_username="default_user",
        default_password="default_pass",
        max_retries=3,
        retry_after=1,
        timeout=30,
        ssl_verify=False,
    )


class TestCiscoClientIOSXEInit:
    def test_init_inherits_from_base_class(self, ios_xe_client, sample_devices):
        assert ios_xe_client.devices == sample_devices
        assert ios_xe_client.default_username == "default_user"
        assert ios_xe_client.default_password == "default_pass"
        assert ios_xe_client.SOLUTION == "iosxe"
        assert ios_xe_client.DEFAULT_PROTOCOL == "restconf"
        assert (
            ios_xe_client.CONFIG_ENDPOINT == "/restconf/data/Cisco-IOS-XE-native:native"
        )


class TestAuthenticateDevice:
    @patch("httpx.Client")
    def test_successful_authentication(self, mock_client_class, ios_xe_client):
        # Setup mock response
        mock_response = MagicMock()
        mock_response.status_code = 200

        # Setup mock client
        mock_client = MagicMock()
        mock_client.get.return_value = mock_response
        mock_client_class.return_value.__enter__.return_value = mock_client

        device = {
            "name": "TestDevice",
            "url": "https://test.example.com",
            "username": "test_user",
            "password": "test_pass",
        }

        result = ios_xe_client.authenticate_device(device)

        assert result is True
        mock_client.get.assert_called_once_with(
            "https://test.example.com/.well-known/host-meta",
            auth=("test_user", "test_pass"),
            timeout=30,
            headers={"Accept": "application/yang-data+json"},
        )

    @patch("httpx.Client")
    def test_authentication_failure_401(self, mock_client_class, ios_xe_client):
        # Setup mock response with 401
        mock_response = MagicMock()
        mock_response.status_code = 401

        # Setup mock client
        mock_client = MagicMock()
        mock_client.get.return_value = mock_response
        mock_client_class.return_value.__enter__.return_value = mock_client

        device = {"name": "TestDevice", "url": "https://test.example.com"}

        result = ios_xe_client.authenticate_device(device)

        assert result is False

    @patch("httpx.Client")
    def test_authentication_connection_error(self, mock_client_class, ios_xe_client):
        # Setup mock client to raise exception
        mock_client = MagicMock()
        mock_client.get.side_effect = httpx.ConnectError("Connection failed")
        mock_client_class.return_value.__enter__.return_value = mock_client

        device = {"name": "TestDevice", "url": "https://test.example.com"}

        result = ios_xe_client.authenticate_device(device)

        assert result is False

    @patch("httpx.Client")
    def test_authentication_uses_default_credentials(
        self, mock_client_class, ios_xe_client
    ):
        # Setup mock response
        mock_response = MagicMock()
        mock_response.status_code = 200

        # Setup mock client
        mock_client = MagicMock()
        mock_client.get.return_value = mock_response
        mock_client_class.return_value.__enter__.return_value = mock_client

        device = {"name": "TestDevice", "url": "https://test.example.com"}

        ios_xe_client.authenticate_device(device)

        # Should use default credentials
        mock_client.get.assert_called_once_with(
            "https://test.example.com/.well-known/host-meta",
            auth=("default_user", "default_pass"),
            timeout=30,
            headers={"Accept": "application/yang-data+json"},
        )


class TestCollectFromDevice:
    @patch("httpx.Client")
    def test_successful_collection(self, mock_client_class, ios_xe_client):
        # Setup mock response with config data
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "Cisco-IOS-XE-native:native": {
                "version": "17.3",
                "hostname": "TestDevice",
                "interface": {"GigabitEthernet": [{"name": "0/0/1"}]},
            }
        }

        # Setup mock client
        mock_client = MagicMock()
        mock_client.get.return_value = mock_response
        mock_client_class.return_value.__enter__.return_value = mock_client

        device = {
            "name": "TestDevice",
            "url": "https://test.example.com",
            "username": "test_user",
            "password": "test_pass",
        }

        result = ios_xe_client.collect_from_device(device)

        assert result is not None
        assert "Cisco-IOS-XE-native:native" in result
        assert result["Cisco-IOS-XE-native:native"]["hostname"] == "TestDevice"

        # Verify correct endpoint was called
        mock_client.get.assert_called_once_with(
            "https://test.example.com/restconf/data/Cisco-IOS-XE-native:native"
        )

    @patch("httpx.Client")
    def test_collection_http_error(self, mock_client_class, ios_xe_client):
        # Setup mock response with error status
        mock_response = MagicMock()
        mock_response.status_code = 404

        # Setup mock client
        mock_client = MagicMock()
        mock_client.get.return_value = mock_response
        mock_client_class.return_value.__enter__.return_value = mock_client

        device = {"name": "TestDevice", "url": "https://test.example.com"}

        result = ios_xe_client.collect_from_device(device)

        assert result is not None
        assert "error" in result
        assert "Failed to collect configuration - HTTP 404" in result["error"]

    @patch("httpx.Client")
    def test_collection_network_exception(self, mock_client_class, ios_xe_client):
        # Setup mock client to raise exception
        mock_client = MagicMock()
        mock_client.get.side_effect = httpx.TimeoutException("Request timeout")
        mock_client_class.return_value.__enter__.return_value = mock_client

        device = {"name": "TestDevice", "url": "https://test.example.com"}

        result = ios_xe_client.collect_from_device(device)

        assert result is not None
        assert "error" in result
        assert "Collection failed - Request timeout" in result["error"]

    @patch("httpx.Client")
    def test_non_restconf_protocol_warning(self, mock_client_class, ios_xe_client):
        # Setup mock response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"config": "data"}

        # Setup mock client
        mock_client = MagicMock()
        mock_client.get.return_value = mock_response
        mock_client_class.return_value.__enter__.return_value = mock_client

        device = {
            "name": "TestDevice",
            "url": "https://test.example.com",
            "protocol": "netconf",  # Non-restconf protocol
        }

        with patch.object(ios_xe_client.logger, "warning") as mock_warning:
            result = ios_xe_client.collect_from_device(device)

            # Should log warning about unsupported protocol
            mock_warning.assert_called_once_with(
                "Protocol netconf not supported yet, using restconf"
            )

            # Should still collect successfully using restconf
            assert result is not None

    @patch("httpx.Client")
    def test_uses_ssl_verify_setting(self, mock_client_class, ios_xe_client):
        # Setup mock response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"config": "data"}

        # Setup mock client
        mock_client = MagicMock()
        mock_client.get.return_value = mock_response
        mock_client_class.return_value.__enter__.return_value = mock_client

        device = {"name": "TestDevice", "url": "https://test.example.com"}

        ios_xe_client.collect_from_device(device)

        # Verify client was created with correct ssl_verify setting
        mock_client_class.assert_called_once_with(
            verify=False,  # Should match ios_xe_client.ssl_verify
            auth=("default_user", "default_pass"),
            timeout=120,  # Should use RESTCONF_DATA_TIMEOUT for data collection
            headers={"Accept": "application/yang-data+json"},
        )


class TestIntegration:
    @patch("httpx.Client")
    def test_full_device_workflow(self, mock_client_class, ios_xe_client):
        # Setup mock responses for both auth and collection
        mock_auth_response = MagicMock()
        mock_auth_response.status_code = 200

        mock_collect_response = MagicMock()
        mock_collect_response.status_code = 200
        mock_collect_response.json.return_value = {
            "Cisco-IOS-XE-native:native": {"hostname": "Switch1"}
        }

        # Setup mock client to return different responses for different URLs
        mock_client = MagicMock()

        def side_effect(url, **kwargs):
            if url.endswith("/.well-known/host-meta"):
                return mock_auth_response
            else:
                return mock_collect_response

        mock_client.get.side_effect = side_effect
        mock_client_class.return_value.__enter__.return_value = mock_client

        device = {
            "name": "Switch1",
            "url": "https://switch1.example.com",
            "username": "admin",
            "password": "cisco123",
        }

        # Test authentication
        auth_result = ios_xe_client.authenticate_device(device)
        assert auth_result is True

        # Test collection
        collect_result = ios_xe_client.collect_from_device(device)
        assert collect_result is not None
        assert "Cisco-IOS-XE-native:native" in collect_result
        assert collect_result["Cisco-IOS-XE-native:native"]["hostname"] == "Switch1"


class TestConstants:
    def test_solution_constant(self):
        assert CiscoClientIOSXE.SOLUTION == "iosxe"

    def test_default_protocol_constant(self):
        assert CiscoClientIOSXE.DEFAULT_PROTOCOL == "restconf"

    def test_config_endpoint_constant(self):
        assert (
            CiscoClientIOSXE.CONFIG_ENDPOINT
            == "/restconf/data/Cisco-IOS-XE-native:native"
        )

    def test_restconf_data_timeout_constant(self):
        assert CiscoClientIOSXE.RESTCONF_DATA_TIMEOUT == 120
