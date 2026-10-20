"""NC-01: RoutedEthernetPorts are selected by policy (not operational ipAddress);
ports without configuration (nvPairs == int_routed_host template defaults, i.e. the
policy NDFC puts on unused ports) are dropped client-side."""

from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from nac_collector.controller.ndfc import CiscoClientNDFC
from nac_collector.resource_manager import ResourceManager

pytestmark = pytest.mark.unit

SETTING = CiscoClientNDFC.ROUTED_PORT_SETTING_KEY

# User-facing parameters + defaults of int_routed_host as returned by the NDFC template
# API (ND 4.3 / NDFC 12.6, identical on 12.5), plus internal ones that must be ignored.
_TEMPLATE_PARAMS = {
    "INTF_VRF": None,
    "IP": None,
    "PREFIX": None,
    "ROUTING_TAG": None,
    "MTU": "9216",
    "SPEED": "Auto",
    "DESC": None,
    "DISABLE_IP_REDIRECTS": "false",
    "ENABLE_PIM_SPARSE": "false",
    "PIM_DR_PRIORITY": "1",
    "FEC": "auto",
    "CONF": None,
    "ADMIN_STATE": "true",
    "ENABLE_NETFLOW": "false",
    "NETFLOW_MONITOR": None,
    "NETFLOW_SAMPLER": None,
    "ENABLE_PFC": "false",
    "ENABLE_QOS": "false",
    "QOS_POLICY": None,
    "QUEUING_POLICY": None,
}
TEMPLATE = {
    "name": "int_routed_host",
    "parameters": [
        {
            "name": n,
            "annotations": {},
            "metaProperties": {"defaultValue": d} if d else {},
        }
        for n, d in _TEMPLATE_PARAMS.items()
    ]
    + [
        {"name": "INTF_NAME", "annotations": {}, "metaProperties": {}},
        {
            "name": "PRIORITY",
            "annotations": {"IsInternal": "true"},
            "metaProperties": {"defaultValue": "500"},
        },
        {
            "name": "POLICY_ID",
            "annotations": {"IsInternal": "true"},
            "metaProperties": {},
        },
    ],
}


@pytest.fixture
def ndfc_client():
    client = CiscoClientNDFC(
        username="admin",
        password="admin_pass",
        base_url="https://ndfc.example.com",
        max_retries=3,
        retry_after=1,
        timeout=5,
        ssl_verify=False,
        fabric_name="test-fabric",
    )
    client.client = (
        MagicMock()
    )  # nested-children processing requires an initialised client
    return client


def _unconfigured(if_name: str, priority: str = "450") -> dict[str, Any]:
    """nvPairs of a routed port nobody configured (as NDFC stores them for unused ports)."""
    return {
        "IP": "",
        "NETFLOW_MONITOR": "",
        "PRIORITY": priority,
        "POLICY_ID": "POLICY-1",
        "INTF_NAME": if_name,
        "DESC": "",
        "MTU": "9216",
        "SPEED": "Auto",
        "PREFIX": "",
        "ENABLE_NETFLOW": "false",
        "ADMIN_STATE": "true",
        "INTF_VRF": "",
        "CONF": "",
        "ROUTING_TAG": "",
    }


def _entry(nv: dict[str, Any] | None, ip_address: str | None = None) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "ifName": "Ethernet1/1",
        "serialNo": "SN1",
        "ipAddress": ip_address,
    }
    if nv is not None:
        entry[SETTING] = nv
    return entry


def _with_template(ndfc_client, template: Any = TEMPLATE):
    return patch.object(ndfc_client, "fetch_data", return_value=template)


class TestIsUnusedRoutedPort:
    @pytest.mark.parametrize("priority", ["450", "500", "1", ""])
    def test_unconfigured_port_is_dropped_regardless_of_priority(
        self, ndfc_client, priority
    ):
        with _with_template(ndfc_client):
            assert ndfc_client._is_unused_routed_port(
                _entry(_unconfigured("Ethernet1/5", priority))
            )

    @pytest.mark.parametrize(
        "field, value",
        [
            ("DESC", "routed without IP"),
            ("IP", "10.0.0.1"),
            ("CONF", "ipv6 address 2001:db8::1/64"),
            ("MTU", "9100"),
            ("ADMIN_STATE", "false"),
            ("ROUTING_TAG", "12"),
            ("INTF_VRF", "TENANT"),
            ("ENABLE_QOS", "true"),
            ("QOS_POLICY", "Q"),
            ("ENABLE_NETFLOW", "true"),
            ("FEC", "rs-fec"),
            ("SPEED", "10Gb"),
        ],
    )
    def test_any_configured_parameter_keeps_the_port(self, ndfc_client, field, value):
        nv = _unconfigured("Ethernet1/21") | {field: value}
        with _with_template(ndfc_client):
            assert not ndfc_client._is_unused_routed_port(_entry(nv, ip_address=None))

    def test_default_vrf_counts_as_unconfigured(self, ndfc_client):
        nv = _unconfigured("Ethernet1/5") | {"INTF_VRF": "default"}
        with _with_template(ndfc_client):
            assert ndfc_client._is_unused_routed_port(_entry(nv))

    def test_comparison_is_case_insensitive(self, ndfc_client):
        nv = _unconfigured("Ethernet1/5") | {"SPEED": "auto", "ADMIN_STATE": "True"}
        with _with_template(ndfc_client):
            assert ndfc_client._is_unused_routed_port(_entry(nv))

    def test_internal_and_identity_parameters_are_ignored(self, ndfc_client):
        nv = _unconfigured("Ethernet1/5") | {
            "POLICY_ID": "POLICY-999",
            "INTF_NAME": "Ethernet1/9",
        }
        with _with_template(ndfc_client):
            assert ndfc_client._is_unused_routed_port(_entry(nv))

    @pytest.mark.parametrize("template", [None, {}, {"parameters": []}, "not-json"])
    def test_template_unavailable_keeps_every_port(self, ndfc_client, template):
        with _with_template(ndfc_client, template):
            assert not ndfc_client._is_unused_routed_port(
                _entry(_unconfigured("Ethernet1/5"))
            )

    def test_missing_nvpairs_falls_back_to_operational_ip(self, ndfc_client):
        with _with_template(ndfc_client) as fetch:
            assert ndfc_client._is_unused_routed_port(_entry(None, ip_address=None))
            assert ndfc_client._is_unused_routed_port(_entry({}, ip_address=None))
            assert not ndfc_client._is_unused_routed_port(
                _entry({}, ip_address="10.0.0.1/30")
            )
            fetch.assert_not_called()

    def test_template_is_read_once(self, ndfc_client):
        with _with_template(ndfc_client) as fetch:
            for _ in range(5):
                ndfc_client._is_unused_routed_port(_entry(_unconfigured("Ethernet1/5")))
            fetch.assert_called_once_with(CiscoClientNDFC.ROUTED_PORT_TEMPLATE_ENDPOINT)


def test_filter_unused_routed_ports(ndfc_client):
    ports = [
        _entry(_unconfigured("Ethernet1/5")),
        _entry(_unconfigured("Ethernet1/21") | {"DESC": "keep"}),
    ]
    with _with_template(ndfc_client):
        assert ndfc_client._filter_unused_routed_ports(ports, "SPINE1") == [ports[1]]


def _routed_parent_endpoint() -> dict[str, Any]:
    endpoints = ResourceManager.get_packaged_endpoint_data("ndfc")
    discovered = next(e for e in endpoints if e["name"] == "Discovered_Switches")
    routed = next(
        c for c in discovered["children"] if c["name"] == "RoutedEthernetPorts"
    )
    return {"name": "Discovered_Switches", "children": [routed]}


def _endpoint_dict() -> dict[str, Any]:
    return {
        "Discovered_Switches": [
            {
                "fabric": "test-fabric",
                "data": [
                    {
                        "logicalName": "SPINE1",
                        "serialNumber": "SN1",
                        "fabricName": "test-fabric",
                        "fid": 7,
                    }
                ],
            }
        ]
    }


def _fake_fetch(nvpairs: dict[str, dict[str, Any]]):
    rows = [{"ifName": name, "serialNo": "SN1", "ipAddress": None} for name in nvpairs]

    def fetch(url: str) -> Any:
        if url == CiscoClientNDFC.ROUTED_PORT_TEMPLATE_ENDPOINT:
            return TEMPLATE
        if "/pti/nvpairs" in url:
            return next(
                nv for name, nv in nvpairs.items() if f"interfaceName={name}&" in url
            )
        assert "ipAddress" not in url  # NC-01: no operational-IP server filter
        return rows

    return fetch


def test_process_switch_interfaces_keeps_configured_routed_ports_only(ndfc_client):
    nvpairs = {
        "Ethernet1/5": _unconfigured("Ethernet1/5"),
        "Ethernet1/21": _unconfigured("Ethernet1/21", "500")
        | {"DESC": "routed without IP", "MTU": "9100"},
        "Ethernet1/22": _unconfigured("Ethernet1/22", "500")
        | {"IP": "10.0.0.1", "PREFIX": "30"},
        "Ethernet1/23": _unconfigured("Ethernet1/23", "500")
        | {"CONF": "ipv6 address 2001:db8::1/64"},
        "Ethernet1/6": _unconfigured("Ethernet1/6"),
    }
    endpoint_dict = _endpoint_dict()
    with patch.object(ndfc_client, "fetch_data", side_effect=_fake_fetch(nvpairs)):
        ndfc_client._process_switch_interfaces(_routed_parent_endpoint(), endpoint_dict)
    switch = endpoint_dict["Discovered_Switches"][0]["data"][0]
    routed = switch["interfaces"]["RoutedEthernetPorts"]
    assert [i["ifName"] for i in routed] == [
        "Ethernet1/21",
        "Ethernet1/22",
        "Ethernet1/23",
    ]
    assert routed[1][SETTING]["IP"] == "10.0.0.1"


def test_process_switch_interfaces_drops_key_when_only_unconfigured_ports(ndfc_client):
    nvpairs = {"Ethernet1/5": _unconfigured("Ethernet1/5")}
    endpoint_dict = _endpoint_dict()
    with patch.object(ndfc_client, "fetch_data", side_effect=_fake_fetch(nvpairs)):
        ndfc_client._process_switch_interfaces(_routed_parent_endpoint(), endpoint_dict)
    switch = endpoint_dict["Discovered_Switches"][0]["data"][0]
    assert "RoutedEthernetPorts" not in switch["interfaces"]
