import concurrent.futures
import json
import logging
import re
import zipfile
from abc import ABC, abstractmethod
from typing import Any


class CiscoClientDevice(ABC):
    """
    Abstract Base Class for controller-less device collection.
    Manages connections to multiple individual devices.
    """

    def __init__(
        self,
        devices: list[dict[str, Any]],
        default_username: str,
        default_password: str,
        max_retries: int,
        retry_after: int,
        timeout: int,
        ssl_verify: bool = False,
    ) -> None:
        self.devices = devices
        self.default_username = default_username
        self.default_password = default_password
        self.max_retries = max_retries
        self.retry_after = retry_after
        self.timeout = timeout
        self.ssl_verify = ssl_verify
        self.logger = logging.getLogger(__name__)

    @abstractmethod
    def authenticate_device(self, device: dict[str, Any]) -> bool:
        """Authenticate to an individual device"""

    @abstractmethod
    def collect_from_device(self, device: dict[str, Any]) -> dict[str, Any]:
        """
        Collect full configuration from a single device.
        Device-based solutions typically have a single endpoint for full config.
        """

    def get_device_credentials(self, device: dict[str, Any]) -> tuple[str, str]:
        """Get credentials for a device (device-specific or defaults)"""
        username = device.get("username", self.default_username)
        password = device.get("password", self.default_password)
        return username, password

    def sanitize_filename(self, name: str) -> str:
        """Sanitize device name to create a valid filename."""
        # First strip whitespace
        sanitized = name.strip()
        # Replace invalid filename characters with underscores
        # Invalid chars: < > : " | ? * / \ and control characters
        sanitized = re.sub(r'[<>:"|?*/\\]', "_", sanitized)
        # Replace multiple consecutive underscores with single underscore
        sanitized = re.sub(r"_+", "_", sanitized)
        # Remove leading/trailing underscores
        sanitized = sanitized.strip("_")
        # Ensure we have a non-empty filename
        if not sanitized:
            sanitized = "device"
        return sanitized

    def collect_and_write_to_archive(self, output: str) -> None:
        """
        Collect from all devices and write individual JSON files to ZIP archive.
        Each device gets its own JSON file named after the device.
        """
        successful = 0
        failed = 0

        with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as zip_file:
            # Collect from devices in parallel
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                futures = {
                    executor.submit(self._collect_with_error_handling, device): device
                    for device in self.devices
                }

                # Process results as they complete
                for future in concurrent.futures.as_completed(futures):
                    device = futures[future]
                    device_name = device.get("name", device.get("url", "unknown"))
                    sanitized_name = self.sanitize_filename(device_name)
                    json_filename = f"{sanitized_name}.json"

                    try:
                        device_data = future.result()
                        if device_data:
                            # Write device data to JSON file in archive
                            json_content = json.dumps(device_data, indent=4)
                            zip_file.writestr(json_filename, json_content)
                            successful += 1
                            self.logger.info(
                                f"Successfully collected from {device_name}"
                            )
                        else:
                            # Write error information for failed device
                            error_data = {
                                "device": device_name,
                                "error": "Collection failed - authentication or connection error",
                            }
                            json_content = json.dumps(error_data, indent=4)
                            zip_file.writestr(json_filename, json_content)
                            failed += 1
                            self.logger.error(f"Failed to collect from {device_name}")
                    except Exception as e:
                        # Write error information for failed device
                        error_data = {"device": device_name, "error": str(e)}
                        json_content = json.dumps(error_data, indent=4)
                        zip_file.writestr(json_filename, json_content)
                        failed += 1
                        self.logger.error(f"Error collecting from {device_name}: {e}")

        self.logger.info(
            f"Collection complete: {successful} successful, {failed} failed. "
            f"Data written to {output}"
        )

    def _collect_with_error_handling(
        self, device: dict[str, Any]
    ) -> dict[str, Any] | None:
        """Wrapper to handle device collection with authentication"""
        try:
            if self.authenticate_device(device):
                return self.collect_from_device(device)
            else:
                self.logger.error(f"Authentication failed for {device.get('name')}")
                return None
        except Exception as e:
            self.logger.error(f"Error with device {device.get('name')}: {e}")
            raise
