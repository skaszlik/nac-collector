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

```cli
Usage: nac-collector [OPTIONS]

  A CLI tool to collect various network configurations.

Options:
  --version                       Show the version and exit.
  -v, --verbosity LVL             Either CRITICAL, ERROR, WARNING, INFO or
                                  DEBUG
  -s, --solution [SDWAN|ISE|NDO|FMC|CATALYSTCENTER]
                                  Solutions supported [SDWAN, ISE, NDO, FMC,
                                  CATALYSTCENTER]  [required]
  -u, --username TEXT             Username for authentication. Can also be set
                                  using the NAC_USERNAME environment variable
                                  [required]
  -p, --password TEXT             Password for authentication. Can also be set
                                  using the NAC_PASSWORD environment variable
                                  [required]
  -url, --url TEXT                Base URL for the service. Can also be set
                                  using the NAC_URL environment variable
                                  [required]
  -g, --git-provider              Generate endpoint.yaml automatically using
                                  provider github repo
  -e, --endpoints-file TEXT       Path to the endpoints YAML file
  -t, --timeout INTEGER           Request timeout in seconds. Default is 30.
  -o, --output TEXT               Path to the output json file
  -h, --help                      Show this message and exit.
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
