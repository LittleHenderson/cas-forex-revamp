"""B09 is a draft-only integration freeze. No runtime switch enables it."""
RELEASE_ENABLED = False


def require_release_enabled():
    # A separately reviewed successor is required; environment/CLI data cannot
    # turn incomplete observer/provider/publication/watchdog work into a grant.
    raise RuntimeError('B09_RELEASE_DISABLED_MISSING_INDEPENDENT_PROVIDERS_AND_WATCHDOG')
