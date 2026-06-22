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
        domain="local",
    )


class TestInitializationWithFabricName:
    """Tests for fabric_name initialization logic."""

    def test_fabric_name_from_kwarg(self):
        client = CiscoClientNDFC(
            username="admin",
            password="pass",
            base_url="https://ndfc.example.com",
            max_retries=3,
            retry_after=1,
            timeout=5,
            ssl_verify=False,
            fabric_name="my-fabric",
        )
        assert client.fabric_name == "my-fabric"

    def test_fabric_name_from_env_var(self, monkeypatch):
        monkeypatch.setenv("NDFC_FABRIC_NAME", "env-fabric")
        client = CiscoClientNDFC(
            username="admin",
            password="pass",
            base_url="https://ndfc.example.com",
            max_retries=3,
            retry_after=1,
            timeout=5,
            ssl_verify=False,
        )
        assert client.fabric_name == "env-fabric"

    def test_fabric_name_kwarg_takes_precedence_over_env(self, monkeypatch):
        monkeypatch.setenv("NDFC_FABRIC_NAME", "env-fabric")
        client = CiscoClientNDFC(
            username="admin",
            password="pass",
            base_url="https://ndfc.example.com",
            max_retries=3,
            retry_after=1,
            timeout=5,
            ssl_verify=False,
            fabric_name="kwarg-fabric",
        )
        assert client.fabric_name == "kwarg-fabric"

    def test_fabric_name_none_when_no_kwarg_and_no_env(self, monkeypatch):
        monkeypatch.delenv("NDFC_FABRIC_NAME", raising=False)
        client = CiscoClientNDFC(
            username="admin",
            password="pass",
            base_url="https://ndfc.example.com",
            max_retries=3,
            retry_after=1,
            timeout=5,
            ssl_verify=False,
        )
        assert client.fabric_name is None

    def test_fabric_name_empty_string_kwarg_falls_back_to_env(self, monkeypatch):
        """Empty string is falsy, so env var fallback should kick in."""
        monkeypatch.setenv("NDFC_FABRIC_NAME", "env-fabric")
        client = CiscoClientNDFC(
            username="admin",
            password="pass",
            base_url="https://ndfc.example.com",
            max_retries=3,
            retry_after=1,
            timeout=5,
            ssl_verify=False,
            fabric_name="",
        )
        assert client.fabric_name == "env-fabric"


class TestInitializationDomain:
    """Tests for domain initialization."""

    def test_domain_defaults_to_local(self):
        client = CiscoClientNDFC(
            username="admin",
            password="pass",
            base_url="https://ndfc.example.com",
            max_retries=3,
            retry_after=1,
            timeout=5,
            ssl_verify=False,
            fabric_name="fabric",
        )
        assert client.domain == "local"

    def test_domain_from_kwarg(self):
        client = CiscoClientNDFC(
            username="admin",
            password="pass",
            base_url="https://ndfc.example.com",
            max_retries=3,
            retry_after=1,
            timeout=5,
            ssl_verify=False,
            fabric_name="fabric",
            domain="DefaultAuth",
        )
        assert client.domain == "DefaultAuth"


class TestInitializationAttributes:
    """Tests for default NDFC-specific attribute initialization."""

    def test_is_msd_fabric_defaults_false(self, ndfc_client):
        assert ndfc_client.is_msd_fabric is False

    def test_msd_topology_defaults_empty(self, ndfc_client):
        assert ndfc_client.msd_topology == {}

    def test_discovered_switches_defaults_empty(self, ndfc_client):
        assert ndfc_client.discovered_switches == {}

    def test_fabric_id_defaults_none(self, ndfc_client):
        assert ndfc_client.fabric_id is None

    def test_exclude_templates_populated(self, ndfc_client):
        assert ndfc_client.exclude_templates == CiscoClientNDFC.EXCLUDE_TEMPLATES
        assert len(ndfc_client.exclude_templates) > 0

    def test_inherited_attributes(self, ndfc_client):
        assert ndfc_client.username == "admin"
        assert ndfc_client.password == "admin_pass"
        assert ndfc_client.base_url == "https://ndfc.example.com"
        assert ndfc_client.max_retries == 3
        assert ndfc_client.retry_after == 1
        assert ndfc_client.timeout == 5
        assert ndfc_client.ssl_verify is False
        assert ndfc_client.client is None
