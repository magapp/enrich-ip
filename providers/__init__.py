"""Provider registry for enrich-ip."""

from providers.ipdb import IPDBProvider
from providers.dnsbl import DNSBLProvider
from providers.ipinfo import IPInfoProvider
from providers.dnsdumpster import DNSDumpsterProvider
from providers.abuseipdb import AbuseIPDBProvider
from providers.proxycheck import ProxycheckProvider

# Registry of all available providers in order of execution
# Order matters: ipinfo must run before dnsdumpster (dependency)
ALL_PROVIDERS = [
    IPDBProvider,
    DNSBLProvider,
    IPInfoProvider,
    DNSDumpsterProvider,
    AbuseIPDBProvider,
    ProxycheckProvider,
]


def get_provider_classes():
    """Return list of all provider classes."""
    return ALL_PROVIDERS


def create_providers():
    """Create instances of all providers."""
    return [provider_class() for provider_class in ALL_PROVIDERS]
