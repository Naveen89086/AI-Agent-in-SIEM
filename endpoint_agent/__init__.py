"""SIEM endpoint agent package.

Collects and submits installed-software inventory (vulnerability detection),
indicator observations (IOC matching) and heartbeats to the SIEM manager.
"""

from endpoint_agent.config import EndpointAgentConfig
from endpoint_agent.transport import EndpointAgentTransport, TransportError

__all__ = ["EndpointAgentConfig", "EndpointAgentTransport", "TransportError"]
