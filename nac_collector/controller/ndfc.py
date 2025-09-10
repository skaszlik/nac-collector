import logging
import json
from typing import Any

import httpx
from nac_collector.controller.base import CiscoClientController


class CiscoClientNDFC(CiscoClientController):
    """
    This class inherits from the abstract class CiscoClientController. It's used for authenticating
    with the Cisco Nexus Dashboard Fabric Controller (NDFC) API and retrieving data from various endpoints.
    Authentication is token-based using domain, username, and password credentials.
    A session is created upon successful authentication for subsequent requests.
    """

    NDFC_AUTH_ENDPOINT = "/login"
    SOLUTION = "ndfc"
    POLICYS_TEMPLATE_NAMES_TO_EXCLUDE = [
        "Default_VRF_Universal", 
        "Default_Network_Universal", 
        "NA", 
        "Default_VRF_Extension_Universal", 
        "Default_Network_Extension_Universal"
    ]

    def __init__(
        self,
        username: str,
        password: str,
        base_url: str,
        max_retries: int,
        retry_after: int,
        timeout: int,
        ssl_verify: bool = False,
        domain: str = "local",
        fabric_name: str = None,
    ):
        super().__init__(
            username, password, base_url, max_retries, retry_after, timeout, ssl_verify
        )
        self.domain = domain
        self.fabric_name = fabric_name
        self.auth_cookie = None
        self.is_msd_fabric = False
        self.msd_topology = None
        self.discovered_switches = []
        self.logger = logging.getLogger(__name__)

    def authenticate(self) -> bool:
        """
        Perform token-based authentication with NDFC.

        Returns:
            bool: True if authentication is successful, False otherwise.
        """
        auth_url = f"{self.base_url}{self.NDFC_AUTH_ENDPOINT}"

        # Prepare authentication payload
        auth_payload = {
            "domain": self.domain,
            "userName": self.username,
            "userPasswd": self.password,
        }

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

        self.logger.debug("Attempting authentication to NDFC at: %s", auth_url)
        self.logger.debug(
            "Authentication payload: %s",
            {
                "domain": self.domain,
                "userName": self.username,
                "userPasswd": "***REMOVED***",
            },
        )

        try:
            # Create the HTTP client with SSL verification setting
            self.client = httpx.Client(
                verify=self.ssl_verify,
                timeout=self.timeout,
                headers=headers
            )
            
            response = self.client.post(auth_url, json=auth_payload)
            
            if response.status_code == 200:
                self.logger.info("Successfully authenticated to NDFC")
                # Extract the authentication cookie
                set_cookie_header = response.headers.get("Set-Cookie")
                if set_cookie_header:
                    # Parse the cookie to extract the session token
                    for cookie in set_cookie_header.split(';'):
                        if cookie.strip().startswith('AuthCookie='):
                            self.auth_cookie = cookie.strip().split('=', 1)[1]
                            break
                    
                    if self.auth_cookie:
                        # Update client headers with the authentication cookie
                        self.client.headers.update({
                            "Cookie": f"AuthCookie={self.auth_cookie}"
                        })
                        return True
                    else:
                        self.logger.error("Authentication cookie not found in response")
                        return False
                else:
                    self.logger.error("Set-Cookie header not found in authentication response")
                    return False
            else:
                self.logger.error(
                    "Authentication failed with status code: %s, response: %s",
                    response.status_code,
                    response.text,
                )
                return False

        except httpx.RequestError as e:
            self.logger.error("Error during authentication: %s", str(e))
            return False
        except Exception as e:
            self.logger.error("Unexpected error during authentication: %s", str(e))
            return False

    def get_from_endpoints_data(self, endpoints_data: list[dict[str, Any]]) -> dict[str, Any]:
        """
        Fetch data from NDFC endpoints based on endpoint definitions.

        Parameters:
            endpoints_data (list[dict[str, Any]]): List of endpoint definitions with name and endpoint keys.

        Returns:
            dict[str, Any]: Dictionary containing the fetched data from all endpoints.
        """
        if not self.client:
            self.logger.error("Client not authenticated. Please authenticate first.")
            return {}

        data = {}
        
        # Check if this is an MSD fabric by attempting to get MSD topology
        if self.fabric_name:
            self._check_msd_fabric()
            self._discover_switches()

        for endpoint_data in endpoints_data:
            endpoint_name = endpoint_data.get("name")
            endpoint_url = endpoint_data.get("endpoint")
            
            if not endpoint_name or not endpoint_url:
                self.logger.warning("Skipping invalid endpoint definition: %s", endpoint_data)
                continue

            # Replace fabric placeholder in URL if fabric_name is provided
            if self.fabric_name and "{fabric_name}" in endpoint_url:
                endpoint_url = endpoint_url.replace("{fabric_name}", self.fabric_name)

            # Handle VPC special processing
            if endpoint_name == "vpc_policies" and self.discovered_switches:
                data[endpoint_name] = self._process_vpc_endpoint_with_filtering(endpoint_url)
                continue
                
            # Skip VPC child endpoints as they're embedded in main VPC data
            if self._is_vpc_child_endpoint(endpoint_name):
                self.logger.debug("Skipping VPC child endpoint %s - data embedded in main VPC endpoint", endpoint_name)
                continue

            full_url = f"{self.base_url}{endpoint_url}"
            self.logger.info("Fetching data from endpoint: %s", endpoint_name)
            
            try:
                response = self.get_request(full_url)
                if response and response.status_code == 200:
                    try:
                        endpoint_data_result = response.json()
                        data[endpoint_name] = endpoint_data_result
                        self.logger.debug("Successfully fetched data from %s", endpoint_name)
                    except json.JSONDecodeError as e:
                        self.logger.error("Failed to parse JSON response from %s: %s", endpoint_name, str(e))
                        data[endpoint_name] = response.text
                else:
                    self.logger.error(
                        "Failed to fetch data from %s. Status: %s",
                        endpoint_name,
                        response.status_code if response else "No response"
                    )
                    data[endpoint_name] = None
                    
            except Exception as e:
                self.logger.error("Error fetching data from %s: %s", endpoint_name, str(e))
                data[endpoint_name] = None

        return data

    def _check_msd_fabric(self):
        """
        Check if the current fabric is an MSD (Multi-Site Domain) fabric and get topology.
        """
        try:
            # Check MSD fabric associations
            msd_endpoint = "/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/control/fabrics/msd/fabric-associations"
            self.logger.info("Checking MSD fabric associations for fabric: %s", self.fabric_name)
            
            response = self.get_request(f"{self.base_url}{msd_endpoint}")
            
            if not response or response.status_code != 200:
                self.logger.info("No MSD fabric associations found. Treating %s as a regular fabric.", self.fabric_name)
                self.is_msd_fabric = False
                return

            try:
                msd_data = response.json()
            except json.JSONDecodeError:
                self.logger.warning("Failed to parse MSD response. Treating %s as a regular fabric.", self.fabric_name)
                self.is_msd_fabric = False
                return
            
            if not msd_data or not isinstance(msd_data, list):
                self.logger.info("No MSD fabric associations found. Treating %s as a regular fabric.", self.fabric_name)
                self.is_msd_fabric = False
                return

            # Check if the provided fabric is MSD root or member
            fabric_parent = None
            fabric_type = None
            fabric_children = []
            
            for fabric_info in msd_data:
                if not isinstance(fabric_info, dict):
                    continue
                    
                fabric_name = fabric_info.get("fabricName")
                if fabric_name == self.fabric_name:
                    fabric_parent = fabric_info.get("fabricParent")
                    fabric_type = fabric_info.get("fabricType")
                    break

            # If fabric not found in associations, treat as regular fabric
            if fabric_parent is None and fabric_type != "MSD":
                self.logger.info("Fabric %s not found in MSD associations. Treating as a regular fabric.", self.fabric_name)
                self.is_msd_fabric = False
                return

            # Check if this is MSD root fabric (fabricType == "MSD" and fabricParent == "None")
            if fabric_type == "MSD" and fabric_parent == "None":
                self.logger.info("Detected MSD root fabric: %s", self.fabric_name)
                self.is_msd_fabric = True
                
                # Collect all child fabrics
                for fabric_info in msd_data:
                    if (isinstance(fabric_info, dict) and 
                        fabric_info.get("fabricParent") == self.fabric_name and
                        fabric_info.get("fabricState") == "member"):
                        fabric_children.append(fabric_info.get("fabricName"))
                
                self.msd_topology = {
                    "fabricParent": self.fabric_name,
                    "fabricChildren": fabric_children
                }
                
                self.logger.info("MSD topology: Parent=%s, Children=%s", self.fabric_name, fabric_children)
            else:
                # This is either a child fabric or not an MSD fabric
                self.logger.info("Fabric %s is not an MSD root fabric (Type: %s, Parent: %s). Treating as a regular fabric.", 
                               self.fabric_name, fabric_type, fabric_parent)
                self.is_msd_fabric = False

        except Exception as e:
            self.logger.error("Error during MSD fabric detection: %s", str(e))
            self.logger.info("Treating %s as a regular fabric due to detection error.", self.fabric_name)
            self.is_msd_fabric = False

    def _discover_switches(self):
        """
        Discover all switches in the fabric to support VPC filtering.
        """
        try:
            switches_endpoint = f"/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/inventory/allswitches/{self.fabric_name}"
            response = self.get_request(f"{self.base_url}{switches_endpoint}")
            
            if response and response.status_code == 200:
                try:
                    switches_data = response.json()
                    if isinstance(switches_data, list):
                        self.discovered_switches = [
                            switch.get("serialNumber") for switch in switches_data 
                            if switch.get("serialNumber")
                        ]
                        self.logger.info("Discovered %d switches in fabric %s", len(self.discovered_switches), self.fabric_name)
                    else:
                        self.logger.warning("Unexpected switches data format")
                except json.JSONDecodeError:
                    self.logger.error("Failed to parse switches data")
            else:
                self.logger.warning("Failed to discover switches for fabric %s", self.fabric_name)
                
        except Exception as e:
            self.logger.error("Error discovering switches: %s", str(e))

    def _process_vpc_endpoint_with_filtering(self, endpoint_url: str) -> list[dict[str, Any]]:
        """
        Process VPC endpoint with client-side serial number filtering.
        
        Parameters:
            endpoint_url (str): The VPC endpoint URL
            
        Returns:
            list[dict[str, Any]]: Filtered VPC data with embedded interface information
        """
        vpc_data = []
        
        if not self.discovered_switches:
            self.logger.warning("No discovered switches available for VPC filtering")
            return vpc_data
            
        # Process each discovered switch serial number
        for serial_number in self.discovered_switches:
            try:
                # Construct VPC URL for this specific switch
                vpc_url = f"{self.base_url}{endpoint_url}?serialNumber={serial_number}"
                response = self.get_request(vpc_url)
                
                if response and response.status_code == 200:
                    try:
                        switch_vpc_data = response.json()
                        if isinstance(switch_vpc_data, list):
                            for vpc_item in switch_vpc_data:
                                if isinstance(vpc_item, dict):
                                    # Add fabric and switch context
                                    vpc_item["fabricName"] = self.fabric_name
                                    vpc_item["switchSerialNumber"] = serial_number
                                    
                                    # Fetch embedded interface data for this VPC
                                    vpc_item = self._enrich_vpc_with_interfaces(vpc_item)
                                    vpc_data.append(vpc_item)
                                    
                        self.logger.debug("Fetched %d VPC entries for switch %s", 
                                        len(switch_vpc_data) if isinstance(switch_vpc_data, list) else 0, 
                                        serial_number)
                                        
                    except json.JSONDecodeError as e:
                        self.logger.error("Failed to parse VPC data for switch %s: %s", serial_number, str(e))
                        
                elif response and response.status_code == 404:
                    # No VPC data for this switch - this is normal
                    self.logger.debug("No VPC data found for switch %s", serial_number)
                else:
                    self.logger.warning("Failed to fetch VPC data for switch %s. Status: %s", 
                                      serial_number, response.status_code if response else "No response")
                                      
            except Exception as e:
                self.logger.error("Error processing VPC data for switch %s: %s", serial_number, str(e))
                
        self.logger.info("Collected %d total VPC entries for fabric %s", len(vpc_data), self.fabric_name)
        return vpc_data

    def _enrich_vpc_with_interfaces(self, vpc_item: dict[str, Any]) -> dict[str, Any]:
        """
        Enrich VPC data with interface information.
        
        Parameters:
            vpc_item (dict): VPC item data
            
        Returns:
            dict: VPC item enriched with interface data
        """
        try:
            # Get peerOneId and peerTwoId for interface lookups
            peer_one_id = vpc_item.get("peerOneId")
            peer_two_id = vpc_item.get("peerTwoId")
            
            if peer_one_id:
                vpc_item["peerOneInterfaces"] = self._get_vpc_interfaces(peer_one_id)
            if peer_two_id:
                vpc_item["peerTwoInterfaces"] = self._get_vpc_interfaces(peer_two_id)
                
        except Exception as e:
            self.logger.error("Error enriching VPC with interfaces: %s", str(e))
            
        return vpc_item

    def _get_vpc_interfaces(self, switch_id: str) -> list[dict[str, Any]]:
        """
        Get VPC interfaces for a specific switch.
        
        Parameters:
            switch_id (str): Switch identifier
            
        Returns:
            list[dict]: List of VPC interfaces
        """
        try:
            interfaces_url = f"{self.base_url}/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/interface/vpc/{self.fabric_name}?serialNumber={switch_id}"
            response = self.get_request(interfaces_url)
            
            if response and response.status_code == 200:
                try:
                    interfaces_data = response.json()
                    if isinstance(interfaces_data, list):
                        return interfaces_data
                except json.JSONDecodeError:
                    self.logger.error("Failed to parse interface data for switch %s", switch_id)
                    
        except Exception as e:
            self.logger.error("Error fetching VPC interfaces for switch %s: %s", switch_id, str(e))
            
        return []

    def _is_vpc_child_endpoint(self, endpoint_name: str) -> bool:
        """
        Check if this is a VPC child endpoint that should be skipped.
        
        Parameters:
            endpoint_name (str): Name of the endpoint
            
        Returns:
            bool: True if this is a VPC child endpoint
        """
        vpc_child_endpoints = [
            "vpc_interfaces",
            "VPC_Peer_Switch_Interfaces", 
            "VPC_Member_Interfaces"
        ]
        return endpoint_name in vpc_child_endpoints

    def get_fabric_details(self) -> dict[str, Any]:
        """
        Get detailed information about the specified fabric.
        
        Returns:
            dict[str, Any]: Fabric details or empty dict if not available.
        """
        if not self.fabric_name:
            self.logger.warning("No fabric name specified")
            return {}
            
        fabric_url = f"{self.base_url}/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/control/fabrics/{self.fabric_name}"
        response = self.get_request(fabric_url)
        
        if response and response.status_code == 200:
            try:
                return response.json()
            except json.JSONDecodeError:
                self.logger.error("Failed to parse fabric details response")
        else:
            self.logger.error("Failed to get fabric details for %s", self.fabric_name)
            
        return {}

    def close(self):
        """
        Close the HTTP client connection.
        """
        if self.client:
            self.client.close()
            self.logger.debug("NDFC client connection closed")
