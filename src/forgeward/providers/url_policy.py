"""Shared transport URL policy for network-backed model providers."""

from __future__ import annotations

from ipaddress import IPv4Address, IPv6Address, ip_address
from urllib.parse import urlsplit

import httpx

from forgeward.providers.base import ProviderError

_MAX_BASE_URL_LENGTH = 2_048


def validate_provider_base_url(
    base_url: str,
    *,
    allow_insecure_http: bool,
    allow_loopback_http: bool = True,
) -> str:
    """Validate a provider URL and enforce encrypted remote transport by default."""
    if (
        not base_url
        or len(base_url) > _MAX_BASE_URL_LENGTH
        or "\\" in base_url
        or "?" in base_url
        or "#" in base_url
        or any(ord(character) <= 0x20 or ord(character) == 0x7F for character in base_url)
    ):
        raise _invalid_base_url()

    try:
        parsed = urlsplit(base_url)
        # httpx applies the same URL grammar used by the actual HTTP adapter.
        httpx.URL(base_url)
        hostname = parsed.hostname
        _ = parsed.port
    except (ValueError, httpx.InvalidURL) as exc:
        raise _invalid_base_url() from exc

    if (
        parsed.scheme.casefold() not in {"http", "https"}
        or not parsed.netloc
        or not hostname
        or parsed.query
        or parsed.fragment
    ):
        raise _invalid_base_url()
    # Checking for '@' also catches deliberately empty userinfo such as https://@host.
    if "@" in parsed.netloc or parsed.username is not None or parsed.password is not None:
        raise ProviderError(
            "Provider credentials must not be embedded in base_url", code="invalid_base_url"
        )

    if (
        parsed.scheme.casefold() == "http"
        and not allow_insecure_http
        and (not allow_loopback_http or not _is_loopback_host(hostname))
    ):
        raise ProviderError(
            "Cleartext HTTP provider URL is not permitted by this adapter policy; "
            "set allow_insecure_http only for an explicitly trusted local network",
            code="insecure_base_url",
        )
    return base_url


def _is_loopback_host(hostname: str) -> bool:
    normalized = hostname.rstrip(".").casefold()
    if normalized == "localhost" or normalized.endswith(".localhost"):
        return True
    try:
        address = ip_address(normalized)
    except ValueError:
        return False
    if address.is_loopback:
        return True
    if isinstance(address, IPv6Address):
        mapped: IPv4Address | None = address.ipv4_mapped
        return bool(mapped and mapped.is_loopback)
    return False


def _invalid_base_url() -> ProviderError:
    return ProviderError(
        "Provider base_url must be an absolute http(s) URL without query or fragment",
        code="invalid_base_url",
    )
