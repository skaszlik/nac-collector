from typing import Any

import httpx

from nac_collector.device.base import CiscoClientDevice


class CiscoClientIOSXE(CiscoClientDevice):
    """
    IOSXE device collection via RESTCONF API.
    Supports Catalyst switches and routers running IOSXE.
    """

    SOLUTION = "iosxe"
    DEFAULT_PROTOCOL = "restconf"
    # Single endpoint to retrieve full configuration
    CONFIG_ENDPOINT = "/restconf/data/Cisco-IOS-XE-native:native"

    def authenticate_device(self, device: dict[str, Any]) -> bool:
        """
        Authenticate to IOSXE device via RESTCONF.
        Uses basic auth, tests with a simple GET request.
        """
        username, password = self.get_device_credentials(device)
        url = device.get("url")

        # Test authentication with RESTCONF root endpoint
        test_url = f"{url}/restconf/data"

        try:
            with httpx.Client(verify=self.ssl_verify) as client:
                response = client.get(
                    test_url,
                    auth=(username, password),
                    timeout=self.timeout,
                    headers={"Accept": "application/yang-data+json"},
                )

                if response.status_code == 200:
                    self.logger.debug(
                        f"Successfully authenticated to {device.get('name')}"
                    )
                    return True
                else:
                    self.logger.error(
                        f"Authentication failed for {device.get('name')}: {response.status_code}"
                    )
                    return False
        except Exception as e:
            self.logger.error(f"Connection error to {device.get('name')}: {e}")
            return False

    def collect_from_device(self, device: dict[str, Any]) -> dict[str, Any]:
        """
        Collect full configuration from IOSXE device via RESTCONF.
        Uses a single endpoint to retrieve the complete native configuration.
        """
        username, password = self.get_device_credentials(device)
        url = device.get("url")
        protocol = device.get("protocol", self.DEFAULT_PROTOCOL)

        if protocol != "restconf":
            self.logger.warning(
                f"Protocol {protocol} not supported yet, using restconf"
            )

        # Construct full URL for configuration endpoint
        config_url = f"{url}{self.CONFIG_ENDPOINT}"

        try:
            with httpx.Client(
                verify=self.ssl_verify,
                auth=(username, password),
                timeout=self.timeout,
                headers={"Accept": "application/yang-data+json"},
            ) as client:
                self.logger.debug(f"Collecting configuration from {device.get('name')}")
                response = client.get(config_url)

                if response.status_code == 200:
                    # Return the full configuration
                    config_data = response.json()
                    self.logger.info(
                        f"Successfully collected configuration from {device.get('name')}"
                    )
                    return config_data  # type: ignore[no-any-return]
                else:
                    self.logger.error(
                        f"Failed to collect configuration from {device.get('name')}: "
                        f"HTTP {response.status_code}"
                    )
                    return {
                        "error": f"Failed to collect configuration - HTTP {response.status_code}"
                    }

        except Exception as e:
            self.logger.error(f"Error collecting from {device.get('name')}: {e}")
            return {"error": f"Collection failed - {str(e)}"}
