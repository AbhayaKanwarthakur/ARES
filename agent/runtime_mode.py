"""Runtime mode controls for demo vs production execution.

The project intentionally keeps a synthetic demo environment separate from a
production-oriented security service. In DEMO mode the dashboard and simulator
are enabled; in PRODUCTION mode they are disabled and only the API/service path
may operate under strict validation and policy controls.
"""

import os

DEMO = "demo"
PRODUCTION = "production"
_ALLOWED = {DEMO, PRODUCTION}


def get_runtime_mode(default=DEMO):
    value = os.environ.get("ARES_RUNTIME_MODE", default).strip().lower()
    if value not in _ALLOWED:
        raise ValueError(f"ARES_RUNTIME_MODE must be one of {sorted(_ALLOWED)}; got {value!r}.")
    return value


def require_demo_mode():
    """Raise if an explicitly demo-only code path is used in production mode."""
    if get_runtime_mode() == PRODUCTION:
        raise RuntimeError("The synthetic demo dashboard is disabled in production mode.")


def require_production_mode():
    """Guard production-only paths so they do not silently run in demo mode."""
    if get_runtime_mode() != PRODUCTION:
        raise RuntimeError("This production-only path requires ARES_RUNTIME_MODE=production.")
