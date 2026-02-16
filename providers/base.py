"""Base provider class for enrich-ip providers."""

from abc import ABC, abstractmethod
from pathlib import Path


class BaseProvider(ABC):
    """Abstract base class for IP enrichment providers."""

    name: str = ""  # Provider name (e.g., "proxycheck")
    requires_api_key: bool = False  # Whether API key is needed
    key_cache_file: str = ""  # Cache filename (e.g., ".enrichip-proxycheck-key")
    headers: list = []  # CSV column headers
    dependencies: list = []  # Other providers this depends on (e.g., dnsdumpster requires ipinfo)

    def __init__(self):
        self.api_key = None
        self.enabled = False
        self.progress_callback = None

    @classmethod
    def add_arguments(cls, parser):
        """Add command line arguments for this provider.

        Override this method to add provider-specific arguments.
        """
        pass

    def initialize(self, args):
        """Initialize the provider with command line arguments.

        Override this method to validate args and load API key from cache.
        Returns True if initialization succeeded, False otherwise.
        """
        return True

    def get_headers(self):
        """Return list of column headers for this provider."""
        return self.headers

    @abstractmethod
    def enrich(self, ip, context):
        """Enrich an IP address with additional information.

        Args:
            ip: The IP address to enrich
            context: A dict for passing data between providers (e.g., hostname)

        Returns:
            A list of values corresponding to the headers, or None on error.
        """
        pass

    def _get_key_path(self):
        """Get the path to the API key cache file."""
        if self.key_cache_file:
            return Path.home() / self.key_cache_file
        return None

    def _load_api_key(self, args, arg_name, provider_display_name):
        """Load API key from args or cache.

        Returns True if key was loaded successfully, False otherwise.
        """
        import sys

        key_from_args = getattr(args, arg_name, None)
        key_path = self._get_key_path()

        if key_from_args:
            self.api_key = key_from_args
            if key_path:
                if key_path.is_dir():
                    key_path.rmdir()
                key_path.write_text(key_from_args)
                print(f"Storing {provider_display_name} key to cache...")
            return True
        elif key_path and key_path.is_file():
            self.api_key = key_path.read_text().strip()
            print(f"Retrieving {provider_display_name} key from cache...")
            return True
        else:
            print(f"Error: --use-{self.name} requires --{self.name}-api", file=sys.stderr)
            return False
