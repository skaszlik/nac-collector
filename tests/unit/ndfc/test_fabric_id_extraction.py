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
        fabric_name="NAC-MSD",
    )


class TestUpdateFabricIdSuccess:
    """Tests for successful fabric ID extraction."""

    def test_fabric_id_from_dict_data(self, ndfc_client):
        result = {
            "Fabric_Configuration": [
                {"fabric": "NAC-MSD", "data": {"id": 12345, "fabricName": "NAC-MSD"}},
            ]
        }

        ndfc_client._update_fabric_id_for_current_fabric(result)

        assert ndfc_client.fabric_id == 12345

    def test_fabric_id_from_list_data(self, ndfc_client):
        result = {
            "Fabric_Configuration": [
                {
                    "fabric": "NAC-MSD",
                    "data": [{"id": 67890, "fabricName": "NAC-MSD"}],
                },
            ]
        }

        ndfc_client._update_fabric_id_for_current_fabric(result)

        assert ndfc_client.fabric_id == 67890

    def test_fabric_id_matches_correct_fabric(self, ndfc_client):
        """When multiple fabrics present, picks the one matching self.fabric_name."""
        result = {
            "Fabric_Configuration": [
                {
                    "fabric": "NAC-SiteA",
                    "data": {"id": 111, "fabricName": "NAC-SiteA"},
                },
                {"fabric": "NAC-MSD", "data": {"id": 222, "fabricName": "NAC-MSD"}},
                {
                    "fabric": "NAC-SiteB",
                    "data": {"id": 333, "fabricName": "NAC-SiteB"},
                },
            ]
        }

        ndfc_client._update_fabric_id_for_current_fabric(result)

        assert ndfc_client.fabric_id == 222


class TestUpdateFabricIdFailure:
    """Tests when fabric ID cannot be extracted."""

    def test_no_fabric_configuration_key(self, ndfc_client):
        result = {"Discovered_Switches": []}

        ndfc_client._update_fabric_id_for_current_fabric(result)

        assert ndfc_client.fabric_id is None

    def test_no_matching_fabric_name(self, ndfc_client):
        result = {
            "Fabric_Configuration": [
                {
                    "fabric": "OTHER-FABRIC",
                    "data": {"id": 999, "fabricName": "OTHER-FABRIC"},
                },
            ]
        }

        ndfc_client._update_fabric_id_for_current_fabric(result)

        assert ndfc_client.fabric_id is None

    def test_data_missing_id_key(self, ndfc_client):
        result = {
            "Fabric_Configuration": [
                {
                    "fabric": "NAC-MSD",
                    "data": {"fabricName": "NAC-MSD", "fabricType": "MFD"},
                },
            ]
        }

        ndfc_client._update_fabric_id_for_current_fabric(result)

        assert ndfc_client.fabric_id is None

    def test_data_is_empty_list(self, ndfc_client):
        result = {
            "Fabric_Configuration": [
                {"fabric": "NAC-MSD", "data": []},
            ]
        }

        ndfc_client._update_fabric_id_for_current_fabric(result)

        assert ndfc_client.fabric_id is None

    def test_data_is_list_without_id(self, ndfc_client):
        result = {
            "Fabric_Configuration": [
                {
                    "fabric": "NAC-MSD",
                    "data": [{"fabricName": "NAC-MSD", "fabricType": "MFD"}],
                },
            ]
        }

        ndfc_client._update_fabric_id_for_current_fabric(result)

        assert ndfc_client.fabric_id is None

    def test_empty_fabric_configuration_list(self, ndfc_client):
        result = {"Fabric_Configuration": []}

        ndfc_client._update_fabric_id_for_current_fabric(result)

        assert ndfc_client.fabric_id is None


class TestUpdateFabricIdForChildFabric:
    """Tests for updating fabric ID when iterating child fabrics in MSD."""

    def test_switches_fabric_context(self):
        """Simulates the MSD processing flow where fabric_name is temporarily changed."""
        client = CiscoClientNDFC(
            username="admin",
            password="pass",
            base_url="https://ndfc.example.com",
            max_retries=3,
            retry_after=1,
            timeout=5,
            ssl_verify=False,
            fabric_name="NAC-SiteA",
        )

        result = {
            "Fabric_Configuration": [
                {
                    "fabric": "NAC-SiteA",
                    "data": {"id": 444, "fabricName": "NAC-SiteA"},
                },
                {
                    "fabric": "NAC-SiteB",
                    "data": {"id": 555, "fabricName": "NAC-SiteB"},
                },
            ]
        }

        client._update_fabric_id_for_current_fabric(result)

        assert client.fabric_id == 444
