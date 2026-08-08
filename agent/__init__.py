"""Standalone Security Configuration Assessment (SCA) endpoint agent.

Runs on monitored endpoints to register itself with the SCA manager, send
heartbeats and collect configuration evidence using the same allowlisted
collectors the server-side engine uses. It has no dependency on the backend
package so it can be deployed to any Python 3.10+ host.

Usage::

    python -m agent register --server http://manager:8000 --agent-code host-a \\
        --registration-token <shared-secret>
    python -m agent scan --rules rules.json --output evidence.json
    python -m agent heartbeat --server http://manager:8000 --agent-code host-a
"""

__version__ = "1.0.0"
