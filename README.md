[![Tests](https://github.com/netascode/nac-collector/actions/workflows/test.yml/badge.svg)](https://github.com/netascode/nac-collector/actions/workflows/test.yml)
![Python Support](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-informational "Python Support: 3.10, 3.11, 3.12, 3.13")

# nac-collector

A CLI tool to collect data from network infrastructure devices. Supports both controller-based architectures (single controller manages multiple devices) and device-based architectures (direct device connections).

## Installation

### Using uv (recommended)

```bash
uv tool install git+https://github.com/netascode/nac-collector.git
```

### Using pip

```bash
pip install git+https://github.com/netascode/nac-collector.git
```

## Usage

The tool supports two types of architectures:
- **Controller-based**: SDWAN, ISE, NDO, FMC, CATALYSTCENTER (require `--url`)
- **Device-based**: IOSXE (requires `--devices-file`)

```
Usage: nac-collector [OPTIONS]

A CLI tool to collect various network configurations.

Options:
  * -s, --solution [SDWAN|ISE|NDO|FMC|CATALYSTCENTER|IOSXE]
                        Solutions supported [required]
  * -u, --username TEXT Username for authentication [required]
                        [env var: NAC_USERNAME]
  * -p, --password TEXT Password for authentication [required]
                        [env var: NAC_PASSWORD]
  * --url TEXT          Base URL for the service (required for controller-based solutions)
                        [env var: NAC_URL]
  -v, --verbosity [CRITICAL|ERROR|WARNING|INFO|DEBUG]
                        Log level [default: WARNING]
  -f, --fetch-latest    Fetch the latest endpoint definitions from
                        upstream sources
  -e, --endpoints-file TEXT
                        Path to the endpoints YAML file
  -t, --timeout INTEGER
                        Request timeout in seconds [default: 30]
  -o, --output TEXT     Path to the output ZIP file [default: nac-collector.zip]
  --devices-file TEXT   Path to the device inventory YAML file (for device-based solutions)
  --version             Show version and exit
  --help                Show this message and exit
```

Set environment variables pointing to supported solution instance:

```shell
export NAC_USERNAME=admin
export NAC_PASSWORD=Cisco123
export NAC_URL=https://10.1.1.1
```

## Examples

### SDWAN

Using uv (development):

```sh
# With environment variables
uv run nac-collector -s SDWAN -v DEBUG --fetch-latest

# Without environment variables
uv run nac-collector -s SDWAN --username USERNAME --password PASSWORD --url URL -v DEBUG --fetch-latest
```

Using installed package:

```sh
nac-collector -s SDWAN -v DEBUG --fetch-latest
```

### ISE

```sh
# With environment variables
nac-collector -s ISE -v DEBUG --fetch-latest

# Without environment variables
nac-collector -s ISE --username USERNAME --password PASSWORD --url URL -v DEBUG --fetch-latest
```

### Catalyst Center

```sh
# With environment variables
nac-collector -s CATALYSTCENTER -v DEBUG --fetch-latest

# Without environment variables
nac-collector -s CATALYSTCENTER --username USERNAME --password PASSWORD --url URL -v DEBUG --fetch-latest
```

Catalyst Center contains some custom logic, explained in [README_catalyst_center.md](README_catalyst_center.md).

### IOSXE (Device-Based Collection)

IOSXE uses a device-based architecture where configuration is collected directly from individual devices using RESTCONF. This requires a device inventory file instead of a single controller URL.

#### Device Inventory File

Create a YAML file with your device inventory:

```yaml
- name: Switch1
  url: https://switch1.example.com
  username: admin
  password: cisco123
  protocol: restconf
- name: Switch2
  url: https://switch2.example.com
  # username/password will use CLI defaults if not specified
- name: Router1
  url: https://router1.example.com
  username: router_admin
  # password will use CLI default
```

#### Usage Examples

```sh
# Using device inventory file
nac-collector -s IOSXE --username admin --password cisco123 --devices-file devices.yaml -v DEBUG

# Using environment variables for default credentials
export NAC_USERNAME=admin
export NAC_PASSWORD=cisco123
nac-collector -s IOSXE --devices-file devices.yaml -v DEBUG

# Custom output file
nac-collector -s IOSXE --devices-file devices.yaml --output my-collection.zip
```

#### Output Format

For device-based collection, the output ZIP archive contains individual JSON files for each device:

```
nac-collector.zip
├── Switch1.json
├── Switch2.json
└── Router1.json
```

Each JSON file contains the complete RESTCONF configuration data for that device.

**Note:** Device-based solutions like IOSXE do not use endpoint files (`--endpoints-file` and `--fetch-latest` are ignored).
