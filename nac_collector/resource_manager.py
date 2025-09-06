"""Resource manager for accessing packaged endpoint files."""

import logging
from importlib import resources
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML

logger = logging.getLogger(__name__)


class ResourceManager:
    """Manages access to packaged endpoint resources."""

    @staticmethod
    def get_packaged_endpoint_path(solution: str) -> str | None:
        """
        Get path to a packaged endpoint YAML file.

        Args:
            solution: The solution name (e.g., 'ise', 'sdwan', etc.)

        Returns:
            Path to the endpoint file if it exists, None otherwise.
        """
        try:
            # Import the endpoints resource package
            from nac_collector.resources import endpoints

            filename = f"{solution.lower()}.yaml"

            # Use importlib.resources to check if the file exists
            if resources.is_resource(endpoints, filename):
                # Get the file path using importlib.resources
                with resources.path(endpoints, filename) as resource_path:
                    logger.debug("Found packaged endpoint file: %s", resource_path)
                    return str(resource_path)
            else:
                logger.debug("Packaged endpoint file not found: %s", filename)
                return None

        except (ImportError, AttributeError, FileNotFoundError) as e:
            logger.debug("Failed to access packaged endpoints: %s", e)
            return None

    @staticmethod
    def get_packaged_endpoint_content(solution: str) -> str | None:
        """
        Get content of a packaged endpoint YAML file.

        Args:
            solution: The solution name (e.g., 'ise', 'sdwan', etc.)

        Returns:
            Content of the endpoint file if it exists, None otherwise.
        """
        try:
            from nac_collector.resources import endpoints

            filename = f"{solution.lower()}.yaml"

            if resources.is_resource(endpoints, filename):
                content = resources.read_text(endpoints, filename)
                logger.debug("Read packaged endpoint content for: %s", solution)
                return content
            else:
                logger.debug("Packaged endpoint file not found: %s", filename)
                return None

        except (ImportError, AttributeError, FileNotFoundError) as e:
            logger.debug("Failed to read packaged endpoint content: %s", e)
            return None

    @staticmethod
    def get_packaged_lookup_content(solution: str) -> dict[str, Any] | list[Any] | None:
        """
        Get content of a packaged lookup YAML file from the lookups subdirectory.

        Args:
            solution: The solution name (e.g., 'catalystcenter', 'ise', etc.)

        Returns:
            Parsed YAML content as dict or list if file exists, None otherwise.
        """
        try:
            # Import the lookups resource package
            from nac_collector.resources import lookups

            filename = f"{solution.lower()}.yaml"

            if resources.is_resource(lookups, filename):
                content = resources.read_text(lookups, filename)
                logger.debug("Read packaged lookup content for: %s", solution)

                yaml = YAML(typ="safe")
                parsed_content: dict[str, Any] = yaml.load(content)
                return parsed_content
            else:
                logger.debug("Packaged lookup file not found: %s", filename)
                return None

        except (ImportError, AttributeError, FileNotFoundError, Exception) as e:
            logger.debug("Failed to read packaged lookup content: %s", e)
            return None

    @staticmethod
    def list_available_solutions() -> list[str]:
        """
        List all available solutions that have packaged endpoint files.

        Returns:
            List of solution names.
        """
        try:
            from nac_collector.resources import endpoints

            available_solutions = []

            # Get all files in the endpoints resource package
            for resource_name in resources.contents(endpoints):
                if resource_name.endswith(".yaml") and not resource_name.startswith(
                    "_"
                ):
                    # Extract solution name from filename
                    solution = resource_name[:-5]  # Remove ".yaml" suffix
                    available_solutions.append(solution)

            logger.debug("Available packaged solutions: %s", available_solutions)
            return sorted(available_solutions)

        except (ImportError, AttributeError) as e:
            logger.debug("Failed to list available solutions: %s", e)
            return []

    @staticmethod
    def resolve_endpoint_file(
        solution: str, explicit_file: str | None = None, use_git_provider: bool = False
    ) -> str | None:
        """
        Resolve endpoint file path using the fallback chain.

        Fallback order:
        1. Explicit --endpoints-file argument
        2. Git provider mode (returns None to trigger git provider logic)
        3. Packaged resource

        Args:
            solution: The solution name
            explicit_file: Explicitly provided file path
            use_git_provider: Whether git provider mode is enabled

        Returns:
            Path to endpoint file, or None if git provider should be used
        """
        # 1. Explicit file argument takes precedence
        if explicit_file:
            if Path(explicit_file).exists():
                logger.info("Using explicit endpoint file: %s", explicit_file)
                return explicit_file
            else:
                logger.warning("Explicit endpoint file not found: %s", explicit_file)
                # Continue to fallback options

        # 2. Git provider mode - return None to let caller handle git provider logic
        if use_git_provider:
            logger.info("Using git provider mode for solution: %s", solution)
            return None

        # 3. Packaged resource
        packaged_path = ResourceManager.get_packaged_endpoint_path(solution)
        if packaged_path:
            logger.info("Using packaged endpoint file: %s", packaged_path)
            return packaged_path

        logger.error("No endpoint file found for solution: %s", solution)
        return None
