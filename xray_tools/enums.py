from enum import Enum

from pydantic import constr


class LogLevel(str, Enum):
    """
    Log level
    "debug" | "info" | "warning" | "error" | "none"
    """

    debug = "debug"
    info = "info"
    warning = "warning"
    error = "error"
    none = "none"


class Network(str, Enum):
    tcp = "tcp"
    kcp = "kcp"
    ws = "ws"
    http = "http"
    domainsocket = "domainsocket"
    quic = "quic"
    grpc = "grpc"


class NetworkRoutingRule(str, Enum):
    tcp = "tcp"
    udp = "udp"
    tcp_udp = "tcp,udp"


class Security(str, Enum):
    none = "none"
    tls = "tls"
    xtls = "xtls"
    reality = "reality"


class DomainStrategy(str, Enum):
    """
    DomainStrategy
    """

    AsIs = "AsIs"
    IPIfNonMatch = "IPIfNonMatch"
    IPOnDemand = "IPOnDemand"


class DomainMatcher(str, Enum):
    """
    DomainMatcher
    """

    hybrid = "hybrid"
    linear = "linear"


class SniffingDest(str, Enum):
    """
    SniffingDest
    """

    http = "http"
    tls = "tls"
    quic = "quic"
    fakedns = "fakedns"
    fakedns_others = "fakedns+others"


class ApiService(str, Enum):
    """
    ApiService
    """

    HandlerService = "HandlerService"
    LoggerService = "LoggerService"
    StatsService = "StatsService"


# Restrict keys to strings that represent a number
PolicyLevelKey = constr(pattern=r"^\d+$")
