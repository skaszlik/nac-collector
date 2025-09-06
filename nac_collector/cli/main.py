import logging
import time
from enum import Enum
from typing import Annotated

import errorhandler
import typer
from rich.console import Console
from rich.logging import RichHandler

import nac_collector
from nac_collector.cisco_client import CiscoClient
from nac_collector.cisco_client_catalystcenter import CiscoClientCATALYSTCENTER
from nac_collector.cisco_client_fmc import CiscoClientFMC
from nac_collector.cisco_client_ise import CiscoClientISE
from nac_collector.cisco_client_ndo import CiscoClientNDO
from nac_collector.cisco_client_sdwan import CiscoClientSDWAN
from nac_collector.constants import GIT_TMP, MAX_RETRIES, RETRY_AFTER, TIMEOUT
from nac_collector.github_repo_wrapper import GithubRepoWrapper
from nac_collector.resource_manager import ResourceManager

console = Console()
logger = logging.getLogger("main")
error_handler = errorhandler.ErrorHandler()


class LogLevel(str, Enum):
    """Supported log levels."""

    CRITICAL = "CRITICAL"
    ERROR = "ERROR"
    WARNING = "WARNING"
    INFO = "INFO"
    DEBUG = "DEBUG"


class Solution(str, Enum):
    """Supported solutions."""

    SDWAN = "SDWAN"
    ISE = "ISE"
    NDO = "NDO"
    FMC = "FMC"
    CATALYSTCENTER = "CATALYSTCENTER"


def configure_logging(level: LogLevel) -> None:
    """Configure logging with Rich handler."""
    level_map = {
        LogLevel.DEBUG: logging.DEBUG,
        LogLevel.INFO: logging.INFO,
        LogLevel.WARNING: logging.WARNING,
        LogLevel.ERROR: logging.ERROR,
        LogLevel.CRITICAL: logging.CRITICAL,
    }

    root_logger = logging.getLogger()
    # Clear existing handlers
    root_logger.handlers.clear()

    # Add Rich handler
    handler = RichHandler(console=console, show_time=True, show_path=False)
    handler.setFormatter(logging.Formatter("%(message)s"))
    root_logger.addHandler(handler)
    root_logger.setLevel(level_map[level])
    error_handler.reset()


def version_callback(value: bool) -> None:
    """Show version and exit."""
    if value:
        console.print(f"nac-collector version: {nac_collector.__version__}")
        raise typer.Exit()


def main(
    solution: Annotated[
        Solution,
        typer.Option(
            "-s",
            "--solution",
            help="Choose a solution",
        ),
    ],
    username: Annotated[
        str,
        typer.Option(
            "-u",
            "--username",
            envvar="NAC_USERNAME",
            help="Username for authentication",
        ),
    ],
    password: Annotated[
        str,
        typer.Option(
            "-p",
            "--password",
            envvar="NAC_PASSWORD",
            help="Password for authentication",
        ),
    ],
    url: Annotated[
        str,
        typer.Option(
            "--url",
            envvar="NAC_URL",
            help="Base URL for the service",
        ),
    ],
    verbosity: Annotated[
        LogLevel,
        typer.Option("-v", "--verbosity", help="Log level"),
    ] = LogLevel.WARNING,
    git_provider: Annotated[
        bool,
        typer.Option(
            "-g",
            "--git-provider",
            help="Generate endpoint.yaml automatically from provider GitHub repo",
        ),
    ] = False,
    endpoints_file: Annotated[
        str | None,
        typer.Option("-e", "--endpoints-file", help="Path to the endpoints YAML file"),
    ] = None,
    timeout: Annotated[
        int,
        typer.Option("-t", "--timeout", help="Request timeout in seconds"),
    ] = TIMEOUT,
    output: Annotated[
        str | None,
        typer.Option("-o", "--output", help="Path to the output JSON file"),
    ] = None,
    version: Annotated[
        bool | None,
        typer.Option(
            "--version", callback=version_callback, help="Show version and exit"
        ),
    ] = None,
) -> None:
    """A CLI tool to collect various network configurations."""

    # Record the start time
    start_time = time.time()

    configure_logging(verbosity)

    # Check for incompatible option combinations
    if git_provider and solution == Solution.NDO:
        console.print(
            "[red]--git-provider option is not supported with NDO solution. The NDO solution uses a different repository structure that is incompatible with the git provider functionality.[/red]"
        )
        raise typer.Exit(1)

    # Resolve endpoint file using fallback chain
    endpoints_yaml_file = ResourceManager.resolve_endpoint_file(
        solution=solution.value.lower(),
        explicit_file=endpoints_file,
        use_git_provider=git_provider,
    )

    if endpoints_yaml_file is None and git_provider:
        # Git provider mode - fetch endpoints from GitHub
        wrapper = GithubRepoWrapper(
            repo_url=f"https://github.com/CiscoDevNet/terraform-provider-{solution.value.lower()}.git",
            clone_dir=GIT_TMP,
            solution=solution.value.lower(),
        )
        wrapper.get_definitions()
        # After git provider runs, the file should be available in current directory
        endpoints_yaml_file = f"endpoints_{solution.value.lower()}.yaml"

    if endpoints_yaml_file is None:
        console.print(
            f"[red]No endpoint file found for solution: {solution.value}[/red]"
        )
        console.print("[yellow]Available options:[/yellow]")
        console.print("1. Use --endpoints-file to specify a custom file")
        console.print("2. Use --git-provider to fetch from GitHub")
        console.print("3. Ensure packaged resources are available")
        raise typer.Exit(1)
    output_file = output or f"{solution.value.lower()}.json"

    cisco_client_class: type[CiscoClient] | None = None
    if solution == Solution.SDWAN:
        cisco_client_class = CiscoClientSDWAN
    elif solution == Solution.ISE:
        cisco_client_class = CiscoClientISE
    elif solution == Solution.NDO:
        cisco_client_class = CiscoClientNDO
    elif solution == Solution.FMC:
        cisco_client_class = CiscoClientFMC
    elif solution == Solution.CATALYSTCENTER:
        cisco_client_class = CiscoClientCATALYSTCENTER

    if cisco_client_class:
        client = cisco_client_class(
            username=username,
            password=password,
            base_url=url,
            max_retries=MAX_RETRIES,
            retry_after=RETRY_AFTER,
            timeout=timeout,
            ssl_verify=False,
        )

        # Authenticate
        if not client.authenticate():
            console.print("[red]Authentication failed. Exiting...[/red]")
            raise typer.Exit(1)

        final_dict = client.get_from_endpoints(endpoints_yaml_file)
        client.write_to_json(final_dict, output_file)

    # Record the stop time
    stop_time = time.time()

    # Calculate the total execution time
    total_time = stop_time - start_time
    logger.info(f"Total execution time: {total_time:.2f} seconds")

    exit_app()


def exit_app() -> None:
    """Exit the application based on error handler state."""
    if error_handler.fired:
        raise typer.Exit(1)
    else:
        raise typer.Exit(0)


def app() -> None:
    """Run the application."""
    typer.run(main)


if __name__ == "__main__":
    app()
