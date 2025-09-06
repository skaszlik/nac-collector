[![Tests](https://github.com/netascode/nac-collector/actions/workflows/test.yml/badge.svg)](https://github.com/netascode/nac-collector/actions/workflows/test.yml)
![Python Support](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-informational "Python Support: 3.10, 3.11, 3.12, 3.13")

# nac-collector

A CLI tool to collect data from network infrastructure devices and systems.

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

```
Usage: nac-collector [OPTIONS]

A CLI tool to collect various network configurations.

Options:
  * -s, --solution [SDWAN|ISE|NDO|FMC|CATALYSTCENTER]
                        Solutions supported [required]
  * -u, --username TEXT Username for authentication [required]
                        [env var: NAC_USERNAME]
  * -p, --password TEXT Password for authentication [required]
                        [env var: NAC_PASSWORD]
  * --url TEXT          Base URL for the service [required]
                        [env var: NAC_URL]
  -v, --verbosity [CRITICAL|ERROR|WARNING|INFO|DEBUG]
                        Log level [default: WARNING]
  -g, --git-provider    Generate endpoint.yaml automatically from
                        provider GitHub repo
  -e, --endpoints-file TEXT
                        Path to the endpoints YAML file
  -t, --timeout INTEGER
                        Request timeout in seconds [default: 30]
  -o, --output TEXT     Path to the output JSON file
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
uv run nac-collector -s SDWAN -v DEBUG --git-provider

# Without environment variables
uv run nac-collector -s SDWAN --username USERNAME --password PASSWORD --url URL -v DEBUG --git-provider
```

Using installed package:

```sh
nac-collector -s SDWAN -v DEBUG --git-provider
```

### ISE

```sh
# With environment variables
nac-collector -s ISE -v DEBUG --git-provider

# Without environment variables
nac-collector -s ISE --username USERNAME --password PASSWORD --url URL -v DEBUG --git-provider
```

### Catalyst Center

```sh
# With environment variables
nac-collector -s CATALYSTCENTER -v DEBUG --git-provider

# Without environment variables
nac-collector -s CATALYSTCENTER --username USERNAME --password PASSWORD --url URL -v DEBUG --git-provider
```

Catalyst Center contains some custom logic, explained in [README_catalyst_center.md](README_catalyst_center.md).
