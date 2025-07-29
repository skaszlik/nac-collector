# NDFC (Nexus Dashboard Fabric Controller) Support

This document describes the NDFC integration added to the nac-collector tool.

## Overview

The `CiscoClientNDFC` class provides support for connecting to Cisco Nexus Dashboard Fabric Controller (NDFC) and collecting configuration data via its REST API.

## Authentication

NDFC uses token-based authentication with the following characteristics:

- **Endpoint**: `POST /login`
- **Authentication Type**: Token-based (JWT)
- **Required Parameters**:
  - `domain`: NDFC domain (default: "local")
  - `userName`: NDFC username
  - `userPasswd`: NDFC password

### Authentication Flow

1. Send POST request to `/login` endpoint with credentials
2. Receive JWT token in response
3. Use token in `Authorization: Bearer <token>` header for subsequent API calls

## Usage

### Command Line

```bash
# Basic usage with default domain (local)
nac-collector -s NDFC -u admin -p password -url https://ndfc.example.com

# With custom domain
nac-collector -s NDFC -u admin -p password -url https://ndfc.example.com -d CustomDomain

# With custom endpoints file and output
nac-collector -s NDFC -u admin -p password -url https://ndfc.example.com \
  -d local -e custom_ndfc_endpoints.yaml -o ndfc_config.json

# With debug logging
nac-collector -s NDFC -u admin -p password -url https://ndfc.example.com \
  -d local -v DEBUG

# Using environment variables
export NAC_USERNAME=admin
export NAC_PASSWORD=password
export NAC_URL=https://ndfc.example.com
export NAC_DOMAIN=local
nac-collector -s NDFC
```

### Parameters

| Parameter | Short | Required | Default | Description |
|-----------|-------|----------|---------|-------------|
| `--solution` | `-s` | Yes | - | Must be set to "NDFC" |
| `--username` | `-u` | Yes | - | NDFC username (or set NAC_USERNAME env var) |
| `--password` | `-p` | Yes | - | NDFC password (or set NAC_PASSWORD env var) |
| `--url` | `-url` | Yes | - | NDFC base URL (or set NAC_URL env var) |
| `--domain` | `-d` | No | "local" | NDFC authentication domain (or set NAC_DOMAIN env var) |
| `--endpoints-file` | `-e` | No | endpoints_ndfc.yaml | Path to endpoints YAML file |
| `--output` | `-o` | No | ndfc.json | Output JSON file path |
| `--verbosity` | `-v` | No | WARNING | Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL) |

### Programmatic Usage

```python
from nac_collector.cisco_client_ndfc import CiscoClientNDFC

# Create client instance with custom domain
client = CiscoClientNDFC(
    username="admin",
    password="password",
    base_url="https://ndfc.example.com",
    domain="CustomDomain",  # Specify your NDFC domain
    max_retries=3,
    retry_after=5,
    timeout=30,
    ssl_verify=False
)

# Test authentication
if client.test_authentication():
    print("Authentication successful!")
    
    # Collect data from endpoints
    data = client.get_from_endpoints("endpoints_ndfc.yaml")
    
    # Write to JSON file
    client.write_to_json(data, "ndfc_output.json")
else:
    print("Authentication failed!")

# Using default domain (local)
client_default = CiscoClientNDFC(
    username="admin",
    password="password",
    base_url="https://ndfc.example.com",
    # domain defaults to "local" if not specified
    max_retries=3,
    retry_after=5,
    timeout=30,
    ssl_verify=False
)
```

### Testing Authentication

A standalone test script is provided to verify NDFC connectivity:

```bash
python test_ndfc_auth.py
```

The script will interactively prompt you for:
- NDFC Base URL (e.g., https://ndfc.example.com)
- Username
- Password (hidden input)
- Domain (defaults to "local" if left blank)

The script will then test the connection and provide detailed feedback.

## Endpoints Configuration

The tool uses YAML files to define which API endpoints to query. A sample `endpoints_ndfc.yaml` file is provided in the `examples/` directory.

### Sample Endpoints

```yaml
# Fabric information
- name: fabrics
  endpoint: /appcenter/cisco/ndfc/api/v1/lan-fabric/rest/control/fabrics

# Switch inventory
- name: switches
  endpoint: /appcenter/cisco/ndfc/api/v1/lan-fabric/rest/inventory/allswitches

# Networks and VRFs
- name: networks
  endpoint: /appcenter/cisco/ndfc/api/v1/lan-fabric/rest/top-down/fabrics/FABRIC_NAME/networks

- name: vrfs
  endpoint: /appcenter/cisco/ndfc/api/v1/lan-fabric/rest/top-down/fabrics/FABRIC_NAME/vrfs
```

**Note**: Some endpoints require fabric-specific names. Replace `FABRIC_NAME` with actual fabric names or implement dynamic resolution.

## Features

### Authentication Testing
- Built-in `test_authentication()` method
- Comprehensive error handling and logging
- Supports multiple token response formats

### Data Processing
- Handles various NDFC response patterns
- Processes nested data structures
- Extracts common identifier fields (id, uuid, fabricName, etc.)

### Error Handling
- Connection timeout handling
- Authentication failure detection
- Comprehensive debug logging
- SSL certificate verification (configurable)

### Logging
- DEBUG level logs for authentication flow
- Request/response logging
- Error and warning messages
- Token detection and session setup logging

## API Endpoints

Common NDFC API endpoints that can be used:

### Fabric Management
- `/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/control/fabrics` - Fabric list
- `/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/control/fabric-settings` - Fabric settings

### Inventory
- `/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/inventory/allswitches` - All switches
- `/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/inventory/switches` - Switch details

### Networking
- `/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/top-down/fabrics/{fabric}/networks` - Networks
- `/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/top-down/fabrics/{fabric}/vrfs` - VRFs

### Policies and Templates
- `/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/control/policies` - Policies
- `/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/policytemplates` - Templates

### Interfaces
- `/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/interface` - Interfaces

### Topology
- `/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/topology/links` - Topology links

## Testing

Unit tests are provided in `tests/ndfc/unit/`:

```bash
# Run NDFC-specific tests
python -m pytest tests/ndfc/unit/

# Run with verbose output
python -m pytest tests/ndfc/unit/ -v

# Run specific test
python -m pytest tests/ndfc/unit/test_authentication.py::TestNDFCAuthentication::test_successful_authentication
```

## Troubleshooting

### Common Issues

1. **Authentication Fails**
   - Verify NDFC URL is correct and accessible
   - Check username/password credentials
   - Ensure domain is correct (default: "local")  
   - Check network connectivity and SSL certificate issues

2. **Token Not Found**
   - NDFC may return token with different key names
   - Check debug logs for actual response structure
   - Update token detection logic if needed

3. **API Calls Fail After Authentication**
   - Verify token format in Authorization header
   - Check if endpoints require fabric-specific paths
   - Ensure user has proper permissions for API access

### Debug Logging

Enable debug logging to troubleshoot issues:

```bash
nac-collector -s NDFC -u admin -p password -url https://ndfc.example.com -v DEBUG
```

This will show:
- Authentication request/response details
- Token detection and session setup
- API call details and responses
- Error messages and stack traces

## Limitations

1. **Git Provider**: The `--git-provider` option is not supported for NDFC as it doesn't have a terraform provider structure
2. **Fabric-Specific Endpoints**: Some endpoints require specific fabric names that must be manually configured
3. **Token Refresh**: Current implementation doesn't handle automatic token refresh

## Future Enhancements

- Automatic fabric name discovery and substitution
- Token refresh mechanism
- Support for multi-domain environments
- Enhanced endpoint templating
- Relationship mapping between different data types
