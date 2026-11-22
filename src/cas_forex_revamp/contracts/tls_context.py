"""Shared thread-safe TLS 1.2+ SSLContext cache for outbound HTTPS clients."""
from __future__ import annotations

import os
import ssl
import threading

_TLS_CONTEXT_CACHE_LOCK = threading.Lock()
_TLS_CONTEXT_CACHE: dict[tuple[str, str, str, str], ssl.SSLContext] = {}


def get_cached_tls12_ssl_context() -> ssl.SSLContext:
    """Return a cached TLS 1.2+ default SSLContext keyed by runtime OpenSSL CA env overrides."""
    verify_paths = ssl.get_default_verify_paths()
    cache_key = (
        verify_paths.cafile or "",
        verify_paths.capath or "",
        os.environ.get(verify_paths.openssl_cafile_env, ""),
        os.environ.get(verify_paths.openssl_capath_env, ""),
    )
    with _TLS_CONTEXT_CACHE_LOCK:
        ctx = _TLS_CONTEXT_CACHE.get(cache_key)
        if ctx is None:
            ctx = ssl.create_default_context()
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            _TLS_CONTEXT_CACHE[cache_key] = ctx
        return ctx
