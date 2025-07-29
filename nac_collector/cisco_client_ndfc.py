import logging
import json
import os

import click
import requests
import urllib3

from nac_collector.cisco_client import CiscoClient

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger("main")

# Suppress urllib3 warnings
logging.getLogger("urllib3").setLevel(logging.ERROR)


class CiscoClientNDFC(CiscoClient):
    """
    This class inherits from the abstract class CiscoClient. It's used for authenticating
    with the Cisco Nexus Dashboard Fabric Controller (NDFC) API and retrieving data from various endpoints.
    Authentication is token-based using domain, username, and password credentials.
    A session is created upon successful authentication for subsequent requests.
    """

    NDFC_AUTH_ENDPOINT = "/login"
    SOLUTION = "ndfc"

    def __init__(
        self,
        username,
        password,
        base_url,
        max_retries,
        retry_after,
        timeout,
        ssl_verify,
        domain="local",
        fabric_name=None,
    ):
        super().__init__(
            username, password, base_url, max_retries, retry_after, timeout, ssl_verify
        )
        self.domain = domain
        self.fabric_name = fabric_name
        self.auth_cookie = None

    def authenticate(self):
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
            "userPasswd": self.password
        }

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

        logger.debug("Attempting authentication to NDFC at: %s", auth_url)
        logger.debug("Authentication payload: %s", {
            "domain": self.domain,
            "userName": self.username,
            "userPasswd": "***REDACTED***"
        })

        try:
            response = requests.post(
                auth_url,
                data=json.dumps(auth_payload),
                headers=headers,
                verify=self.ssl_verify,
                timeout=self.timeout,
            )

            logger.debug("Authentication response status code: %s", response.status_code)
            logger.debug("Authentication response headers: %s", dict(response.headers))

            if response and response.status_code == 200:
                logger.info("Authentication successful for NDFC URL: %s", auth_url)
                
                # Parse response to get token
                response_data = response.json()
                logger.debug("Authentication response data: %s", response_data)
                
                # NDFC typically returns the token in the response
                # The exact key may vary, common patterns are 'token', 'access_token', or 'Jwt_Token'
                token = None
                for token_key in ['token', 'access_token', 'Jwt_Token', 'jwttoken']:
                    if token_key in response_data:
                        token = response_data[token_key]
                        logger.debug("Found token with key: %s", token_key)
                        break
                
                if not token:
                    logger.error("No valid token found in authentication response")
                    logger.debug("Available keys in response: %s", list(response_data.keys()))
                    return False

                # Extract AuthCookie from response headers for future API calls
                auth_cookie = None
                set_cookie_header = response.headers.get('Set-Cookie')
                if set_cookie_header:
                    # Parse AuthCookie from Set-Cookie header
                    for cookie in set_cookie_header.split(','):
                        if 'AuthCookie=' in cookie:
                            auth_cookie = cookie.split('AuthCookie=')[1].split(';')[0]
                            break
                    
                if auth_cookie:
                    self.auth_cookie = auth_cookie
                    logger.debug("Extracted AuthCookie for future API calls")
                else:
                    logger.warning("No AuthCookie found in response headers")

                # Create a session after successful authentication
                self.session = requests.Session()
                self.session.headers.update({
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "Authorization": f"Bearer {token}",
                })
                
                # Add AuthCookie to session if available
                if self.auth_cookie:
                    self.session.cookies.set('AuthCookie', self.auth_cookie)
                
                logger.debug("Session headers configured: %s", dict(self.session.headers))
                logger.info("NDFC authentication completed successfully")
                
                # If fabric_name is provided, fetch and save fabric settings
                if self.fabric_name:
                    self.fetch_and_save_fabric_settings()
                
                return True

            else:
                logger.error(
                    "NDFC authentication failed with status code: %s",
                    response.status_code,
                )
                if response.text:
                    logger.debug("Authentication error response: %s", response.text)
                return False

        except requests.exceptions.Timeout:
            logger.error("Authentication request timed out after %s seconds", self.timeout)
            return False
        except requests.exceptions.ConnectionError as e:
            logger.error("Connection error during authentication: %s", str(e))
            return False
        except json.JSONDecodeError as e:
            logger.error("Failed to decode JSON response during authentication: %s", str(e))
            return False
        except Exception as e:
            logger.error("Unexpected error during authentication: %s", str(e))
            return False

    def fetch_and_save_fabric_settings(self):
        """
        Fetch fabric settings for the specified fabric and save to JSON file.
        Uses AuthCookie for authentication.
        
        Returns:
            bool: True if successful, False otherwise.
        """
        if not self.fabric_name:
            logger.error("No fabric name provided for fabric settings retrieval")
            return False
            
        if not self.session:
            logger.error("No authenticated session available")
            return False
            
        # Construct the fabric settings API endpoint
        fabric_endpoint = f"/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/control/fabrics/{self.fabric_name}"
        fabric_url = f"{self.base_url}{fabric_endpoint}"
        
        logger.info("Fetching fabric settings for fabric: %s", self.fabric_name)
        logger.debug("Fabric settings URL: %s", fabric_url)
        
        try:
            # Make the API call using the authenticated session with AuthCookie
            response = self.session.get(
                fabric_url,
                verify=self.ssl_verify,
                timeout=self.timeout
            )
            
            logger.debug("Fabric settings response status code: %s", response.status_code)
            
            if response.status_code == 200:
                try:
                    fabric_data = response.json()
                    logger.info("Successfully retrieved fabric settings for: %s", self.fabric_name)
                    logger.debug("Fabric settings data keys: %s", list(fabric_data.keys()) if isinstance(fabric_data, dict) else "Non-dict response")
                    
                    # Create resources directory if it doesn't exist
                    resources_dir = os.path.join(os.path.dirname(__file__), "resources")
                    if not os.path.exists(resources_dir):
                        os.makedirs(resources_dir)
                        logger.debug("Created resources directory: %s", resources_dir)
                    
                    # Save fabric settings to JSON file
                    filename = f"NDFC_{self.fabric_name}_fabric_settings.json"
                    filepath = os.path.join(resources_dir, filename)
                    
                    with open(filepath, 'w', encoding='utf-8') as f:
                        json.dump(fabric_data, f, indent=4, ensure_ascii=False)
                    
                    logger.info("Fabric settings saved to: %s", filepath)
                    return True
                    
                except json.JSONDecodeError as e:
                    logger.error("Failed to decode JSON response for fabric settings: %s", str(e))
                    logger.debug("Raw response content: %s", response.text[:500])
                    return False
                    
            else:
                logger.error("Failed to fetch fabric settings. Status code: %s", response.status_code)
                logger.debug("Error response: %s", response.text[:500] if response.text else "No response text")
                return False
                
        except requests.exceptions.Timeout:
            logger.error("Fabric settings request timed out after %s seconds", self.timeout)
            return False
        except requests.exceptions.ConnectionError as e:
            logger.error("Connection error during fabric settings retrieval: %s", str(e))
            return False
        except Exception as e:
            logger.error("Unexpected error during fabric settings retrieval: %s", str(e))
            return False

    def test_authentication(self):
        """
        Test method to verify if authentication to NDFC server is working.
        
        Returns:
            bool: True if authentication test passes, False otherwise.
        """
        logger.info("Starting NDFC authentication test...")
        logger.debug("Test parameters - Base URL: %s, Username: %s, Domain: %s", 
                    self.base_url, self.username, self.domain)
        
        # Attempt authentication
        auth_result = self.authenticate()
        
        if auth_result:
            logger.info("✓ NDFC authentication test PASSED")
            logger.debug("Session established successfully with headers: %s", 
                        dict(self.session.headers) if self.session else "No session")
            
            # Optionally test a simple API call to verify the session works
            try:
                # Common NDFC endpoint to test connectivity (adjust as needed)
                test_endpoint = "/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/control/fabrics"
                test_url = f"{self.base_url}{test_endpoint}"
                
                logger.debug("Testing API connectivity with endpoint: %s", test_endpoint)
                test_response = self.session.get(
                    test_url,
                    verify=self.ssl_verify,
                    timeout=self.timeout
                )
                
                logger.debug("Test API call status code: %s", test_response.status_code)
                
                if test_response.status_code in [200, 201, 202]:
                    logger.info("✓ NDFC API connectivity test PASSED")
                elif test_response.status_code == 401:
                    logger.warning("⚠ Authentication successful but API call unauthorized - token may be invalid")
                elif test_response.status_code == 404:
                    logger.info("✓ Authentication successful (API endpoint not found is expected for test)")
                else:
                    logger.warning("⚠ Authentication successful but API test returned status: %s", 
                                 test_response.status_code)
                    
            except Exception as e:
                logger.warning("Authentication successful but API test failed: %s", str(e))
                
            return True
        else:
            logger.error("✗ NDFC authentication test FAILED")
            return False

    def process_endpoint_data(self, endpoint, endpoint_dict, data, id_=None):
        """
        Process the data for a given endpoint and update the endpoint_dict.
        This is a basic implementation that can be extended based on NDFC API response patterns.

        Parameters:
            endpoint (dict): The endpoint configuration.
            endpoint_dict (dict): The dictionary to store processed data.
            data (dict or list): The data fetched from the endpoint.
            id_ (str, optional): Optional ID parameter.

        Returns:
            dict: The updated endpoint dictionary with processed data.
        """
        if data is None:
            endpoint_dict[endpoint["name"]].append(
                {"data": {}, "endpoint": endpoint["endpoint"]}
            )
            return endpoint_dict

        # Handle different response patterns from NDFC
        if isinstance(data, list):
            # Direct list response
            endpoint_dict[endpoint["name"]].append(
                {"data": data, "endpoint": endpoint["endpoint"]}
            )
        elif isinstance(data, dict):
            # Check for common NDFC response patterns
            if "data" in data:
                # Response has a 'data' wrapper
                endpoint_dict[endpoint["name"]].append(
                    {"data": data["data"], "endpoint": endpoint["endpoint"]}
                )
            elif "response" in data:
                # Response has a 'response' wrapper
                endpoint_dict[endpoint["name"]].append(
                    {"data": data["response"], "endpoint": endpoint["endpoint"]}
                )
            else:
                # Direct object response
                endpoint_dict[endpoint["name"]].append(
                    {"data": data, "endpoint": endpoint["endpoint"]}
                )

        return endpoint_dict

    def get_from_endpoints(self, endpoints_yaml_file):
        """
        Retrieve data from a list of endpoints specified in a YAML file and
        run GET requests to download data from NDFC controller.

        Parameters:
            endpoints_yaml_file (str): The name of the YAML file containing the endpoints.

        Returns:
            dict: The final dictionary containing the data retrieved from the endpoints.
        """
        logger.info("Loading NDFC endpoints from %s", endpoints_yaml_file)
        
        try:
            with open(endpoints_yaml_file, "r", encoding="utf-8") as f:
                endpoints = self.yaml.load(f)
        except FileNotFoundError:
            logger.error("Endpoints file not found: %s", endpoints_yaml_file)
            return {}
        except Exception as e:
            logger.error("Error loading endpoints file: %s", str(e))
            return {}

        # Initialize an empty dictionary
        final_dict = {}

        # Iterate over all endpoints
        with click.progressbar(endpoints, label="Processing NDFC endpoints") as endpoint_bar:
            for endpoint in endpoint_bar:
                logger.info("Processing NDFC endpoint: %s", endpoint["name"])
                endpoint_dict = CiscoClient.create_endpoint_dict(endpoint)
                
                # Replace FABRIC_NAME placeholder with actual fabric name if provided
                endpoint_url = endpoint["endpoint"]
                if self.fabric_name and "FABRIC_NAME" in endpoint_url:
                    endpoint_url = endpoint_url.replace("FABRIC_NAME", self.fabric_name)
                    logger.debug("Replaced FABRIC_NAME with %s in endpoint: %s", self.fabric_name, endpoint_url)
                
                # Fetch data from the endpoint
                data = self.fetch_data(endpoint_url)
                
                # Process the endpoint data and get the updated dictionary
                endpoint_dict = self.process_endpoint_data(
                    endpoint, endpoint_dict, data
                )
                
                # TODO: Add support for children endpoints if needed for NDFC
                # This can be implemented similar to the Catalyst Center implementation
                
                # Save results to dictionary
                final_dict.update(endpoint_dict)
                
        logger.info("Completed processing %d NDFC endpoints", len(endpoints))
        return final_dict

    @staticmethod
    def get_id_value(item):
        """
        Attempts to get an identifier value from a dictionary.
        Common NDFC ID fields to check.

        Parameters:
            item (dict): The dictionary to get the identifier value from.

        Returns:
            str or None: The identifier value if it exists, None otherwise.
        """
        # Common NDFC identifier fields
        id_fields = ["id", "uuid", "fabricName", "name", "serialNumber", "switchDbId"]
        
        for field in id_fields:
            value = item.get(field)
            if value is not None:
                return str(value)
        
        return None
