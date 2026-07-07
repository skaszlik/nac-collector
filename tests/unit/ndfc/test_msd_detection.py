from unittest.mock import patch

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


ENDPOINTS_WITH_MSD = [
    {"name": "MSD_Fabric_Associations", "endpoint": "/rest/control/fabrics/msd"},
    {"name": "Fabric_Configuration", "endpoint": "/rest/control/fabrics/%v"},
    {"name": "Discovered_Switches", "endpoint": "/rest/control/fabrics/%v/switches"},
]

ENDPOINTS_WITHOUT_MSD = [
    {"name": "Fabric_Configuration", "endpoint": "/rest/control/fabrics/%v"},
    {"name": "Discovered_Switches", "endpoint": "/rest/control/fabrics/%v/switches"},
]


class TestMsdDetectionNoEndpoint:
    """Tests when MSD endpoint is not in YAML."""

    def test_no_msd_endpoint_sets_single_site(self, ndfc_client):
        ndfc_client._detect_msd_fabric_from_endpoints(ENDPOINTS_WITHOUT_MSD)

        assert ndfc_client.is_msd_fabric is False
        assert ndfc_client.msd_topology == {}


class TestMsdDetectionEmptyData:
    """Tests when MSD endpoint exists but returns no data."""

    def test_empty_msd_data_sets_single_site(self, ndfc_client):
        with patch.object(ndfc_client, "fetch_data", return_value=None):
            ndfc_client._detect_msd_fabric_from_endpoints(ENDPOINTS_WITH_MSD)

        assert ndfc_client.is_msd_fabric is False

    def test_empty_list_msd_data_sets_single_site(self, ndfc_client):
        with patch.object(ndfc_client, "fetch_data", return_value=[]):
            ndfc_client._detect_msd_fabric_from_endpoints(ENDPOINTS_WITH_MSD)

        assert ndfc_client.is_msd_fabric is False


class TestMsdDetectionFabricIsRoot:
    """Tests when target fabric is the MSD root."""

    def test_fabric_is_msd_root(self, ndfc_client):
        msd_associations = [
            {"fabricName": "NAC-MSD", "fabricState": "msd", "fabricParent": "None"},
            {
                "fabricName": "NAC-SiteA",
                "fabricState": "member",
                "fabricParent": "NAC-MSD",
            },
            {
                "fabricName": "NAC-SiteB",
                "fabricState": "member",
                "fabricParent": "NAC-MSD",
            },
            {
                "fabricName": "NAC-ISN",
                "fabricState": "member",
                "fabricParent": "NAC-MSD",
            },
        ]

        with patch.object(ndfc_client, "fetch_data", return_value=msd_associations):
            ndfc_client._detect_msd_fabric_from_endpoints(ENDPOINTS_WITH_MSD)

        assert ndfc_client.is_msd_fabric is True
        assert ndfc_client.msd_topology["msd_root"] == "NAC-MSD"
        assert set(ndfc_client.msd_topology["member_fabrics"]) == {
            "NAC-SiteA",
            "NAC-SiteB",
            "NAC-ISN",
        }
        assert "NAC-MSD" in ndfc_client.msd_topology["all_fabrics"]

    def test_msd_root_only_collects_own_members(self, ndfc_client):
        """When multiple MSD roots exist, only collect members of target fabric."""
        msd_associations = [
            {"fabricName": "NAC-MSD", "fabricState": "msd", "fabricParent": "None"},
            {
                "fabricName": "NAC-SiteA",
                "fabricState": "member",
                "fabricParent": "NAC-MSD",
            },
            {
                "fabricName": "OTHER-MSD",
                "fabricState": "msd",
                "fabricParent": "None",
            },
            {
                "fabricName": "OTHER-Site",
                "fabricState": "member",
                "fabricParent": "OTHER-MSD",
            },
        ]

        with patch.object(ndfc_client, "fetch_data", return_value=msd_associations):
            ndfc_client._detect_msd_fabric_from_endpoints(ENDPOINTS_WITH_MSD)

        assert ndfc_client.is_msd_fabric is True
        assert "NAC-SiteA" in ndfc_client.msd_topology["member_fabrics"]
        assert "OTHER-Site" not in ndfc_client.msd_topology["member_fabrics"]


class TestMsdDetectionFabricIsMember:
    """Tests when target fabric is a member (not root)."""

    def test_member_fabric_treated_as_standalone(self):
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

        msd_associations = [
            {"fabricName": "NAC-MSD", "fabricState": "msd", "fabricParent": "None"},
            {
                "fabricName": "NAC-SiteA",
                "fabricState": "member",
                "fabricParent": "NAC-MSD",
            },
        ]

        with patch.object(client, "fetch_data", return_value=msd_associations):
            client._detect_msd_fabric_from_endpoints(ENDPOINTS_WITH_MSD)

        assert client.is_msd_fabric is False


class TestMsdDetectionExceptionHandling:
    """Tests for graceful error handling during MSD detection."""

    def test_exception_during_fetch_falls_back_to_single_site(self, ndfc_client):
        with patch.object(
            ndfc_client, "fetch_data", side_effect=Exception("Network error")
        ):
            ndfc_client._detect_msd_fabric_from_endpoints(ENDPOINTS_WITH_MSD)

        assert ndfc_client.is_msd_fabric is False

    def test_malformed_association_data_handled(self, ndfc_client):
        """Non-dict entries in the list should be silently skipped."""
        msd_associations = [
            "not-a-dict",
            None,
            {"fabricName": "NAC-MSD", "fabricState": "msd", "fabricParent": "None"},
            {
                "fabricName": "NAC-SiteA",
                "fabricState": "member",
                "fabricParent": "NAC-MSD",
            },
        ]

        with patch.object(ndfc_client, "fetch_data", return_value=msd_associations):
            ndfc_client._detect_msd_fabric_from_endpoints(ENDPOINTS_WITH_MSD)

        assert ndfc_client.is_msd_fabric is True
        assert "NAC-SiteA" in ndfc_client.msd_topology["member_fabrics"]
