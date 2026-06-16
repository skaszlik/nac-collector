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


class TestParseVpcEntityIdValid:
    """Tests for valid vpcEntityId parsing."""

    def test_standard_format(self, ndfc_client):
        vpc_pair, vpc_name = ndfc_client._parse_vpc_entity_id(
            "FDO26260888~FDO26260897~vpc10"
        )

        assert vpc_pair == "FDO26260888~FDO26260897"
        assert vpc_name == "vpc10"

    def test_different_serial_formats(self, ndfc_client):
        vpc_pair, vpc_name = ndfc_client._parse_vpc_entity_id(
            "SAL12345ABC~SAL67890DEF~vpc1"
        )

        assert vpc_pair == "SAL12345ABC~SAL67890DEF"
        assert vpc_name == "vpc1"

    def test_vpc_name_with_large_number(self, ndfc_client):
        vpc_pair, vpc_name = ndfc_client._parse_vpc_entity_id(
            "SERIAL1~SERIAL2~vpc999"
        )

        assert vpc_pair == "SERIAL1~SERIAL2"
        assert vpc_name == "vpc999"


class TestParseVpcEntityIdInvalid:
    """Tests for invalid vpcEntityId inputs."""

    def test_empty_string(self, ndfc_client):
        vpc_pair, vpc_name = ndfc_client._parse_vpc_entity_id("")

        assert vpc_pair is None
        assert vpc_name is None

    def test_none_input(self, ndfc_client):
        vpc_pair, vpc_name = ndfc_client._parse_vpc_entity_id(None)

        assert vpc_pair is None
        assert vpc_name is None

    def test_non_string_input(self, ndfc_client):
        vpc_pair, vpc_name = ndfc_client._parse_vpc_entity_id(12345)

        assert vpc_pair is None
        assert vpc_name is None

    def test_too_few_parts(self, ndfc_client):
        vpc_pair, vpc_name = ndfc_client._parse_vpc_entity_id("SERIAL1~vpc10")

        assert vpc_pair is None
        assert vpc_name is None

    def test_too_many_parts(self, ndfc_client):
        vpc_pair, vpc_name = ndfc_client._parse_vpc_entity_id(
            "SERIAL1~SERIAL2~extra~vpc10"
        )

        assert vpc_pair is None
        assert vpc_name is None

    def test_single_value_no_tildes(self, ndfc_client):
        vpc_pair, vpc_name = ndfc_client._parse_vpc_entity_id("no-tildes-here")

        assert vpc_pair is None
        assert vpc_name is None

    def test_vpc_name_does_not_start_with_vpc(self, ndfc_client):
        vpc_pair, vpc_name = ndfc_client._parse_vpc_entity_id(
            "SERIAL1~SERIAL2~portchannel10"
        )

        assert vpc_pair is None
        assert vpc_name is None

    def test_vpc_name_uppercase_not_matched(self, ndfc_client):
        """vpc prefix check is case-sensitive — 'VPC10' should fail."""
        vpc_pair, vpc_name = ndfc_client._parse_vpc_entity_id(
            "SERIAL1~SERIAL2~VPC10"
        )

        assert vpc_pair is None
        assert vpc_name is None
