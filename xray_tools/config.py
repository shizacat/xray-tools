"""
Example:

{
  "log": {
    "loglevel": "info"
  },
  "routing": {
    "rules": [],
    "domainStrategy": "AsIs"
  },
  "inbounds": [
    {
      "port": 443,
      "protocol": "vless",
      "tag": "vless_tls",
      "settings": {
        "clients": [
          {
            "id": "{{ xray.uuid }}",
            "email": "user@{{ ansible_fqdn }}",
            "flow": "xtls-rprx-vision"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "www.microsoft.com:443",
          "xver": 0,
          "serverNames": [
            "www.microsoft.com"
          ],
          "privateKey": "{{ xray.x25519_private }}",
          "minClientVer": "",
          "maxClientVer": "",
          "maxTimeDiff": 0,
          "shortIds": [
            "{{ xray.short_id }}"
          ]
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls"
        ]
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "tag": "direct"
    },
    {
      "protocol": "blackhole",
      "tag": "block"
    }
  ]
}
"""

from __future__ import annotations

from enum import Enum
from typing import TextIO, Optional, List, Dict, Type, ClassVar, Union

from pydantic import (
    BaseModel,
    Field,
    model_validator,
    constr,
)

from .protocols import (
    InboundProtocol,
    ProtocolSettingsBase,
    ProtocolSettingsVless,
    ProtocolSettingsDokodemoDoor,
)
from .base import BaseModelConfig


# --- Enums ---

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


# --- Classes ---

class Stats(BaseModelConfig):
    """
    Включает сбор статистики
    """


class Api(BaseModelConfig):
    """
    API interface configuration provides a set
    of APIs based on gRPC for remote invocation.

    Example
    {
        "api": {
            "tag": "api",
            "listen": "127.0.0.1:8080",
            "services": ["HandlerService", "LoggerService", "StatsService"]
        }
    }
    """

    tag: str = Field(..., description="The identifier of this inbound connection")
    listen: Optional[str] = Field(
        None, description="The listening address. Example: 127.0.0.1:8080"
    )
    services: List[ApiService] = Field(
        default_factory=list,
        description=(
            "The list of services to be enabled. "
            "Available services: HandlerService, LoggerService, StatsService"
        ),
    )


class Log(BaseModelConfig):
    access: Optional[str] = Field(None, description="путь к файлу")
    error: Optional[str] = Field(None, description="путь к файлу")
    loglevel: LogLevel = Field(LogLevel.none)
    dnsLog: bool = Field(False)


# Restrict keys to strings that represent a number
PolicyLevelKey = constr(pattern=r"^\d+$")


class PolicyLevel(BaseModelConfig):
    """
    Level Policy Object
    """

    handshake: Optional[int] = Field(None, description="Handshake timeout in seconds")
    connIdle: Optional[int] = Field(None, description="Idle timeout in seconds")
    uplinkOnly: Optional[int] = Field(
        None, description="Uplink only timeout in seconds"
    )
    downlinkOnly: Optional[int] = Field(
        None, description="Downlink only timeout in seconds"
    )
    statsUserUplink: Optional[bool] = Field(
        None, description="Enable statistics collection for user uplink"
    )
    statsUserDownlink: Optional[bool] = Field(
        None, description="Enable statistics collection for user downlink"
    )
    statsUserOnline: Optional[bool] = Field(
        None, description="Enable statistics collection for user online"
    )
    bufferSize: Optional[int] = Field(None, description="Buffer size in bytes")


class PolicySystem(BaseModelConfig):
    """Policy System"""

    statsInboundUplink: Optional[bool] = Field(
        None, description="Enable statistics collection for inbound uplink"
    )
    statsInboundDownlink: Optional[bool] = Field(
        None, description="Enable statistics collection for inbound downlink"
    )
    statsOutboundUplink: Optional[bool] = Field(
        None, description="Enable statistics collection for outbound uplink"
    )
    statsOutboundDownlink: Optional[bool] = Field(
        None, description="Enable statistics collection for outbound downlink"
    )


class Policy(BaseModelConfig):
    """
    Local Policy
    Local policy can be used to set different policy settings
    for different user levels

    {
        "policy": {
            "levels": {
                "0": {
                    "handshake": 4,
                    "connIdle": 300,
                    "uplinkOnly": 2,
                    "downlinkOnly": 5,
                    "statsUserUplink": false,
                    "statsUserDownlink": false,
                    "statsUserOnline": false,
                    "bufferSize": 4
                }
            },
            "system": {
                "statsInboundUplink": false,
                "statsInboundDownlink": false,
                "statsOutboundUplink": false,
                "statsOutboundDownlink": false
            }
        }
    }
    """

    levels: Dict[PolicyLevelKey, PolicyLevel] = Field(
        default_factory=dict,
        description=(
            "Local policy can be used to set different policy settings "
            "for different user levels"
            "Key: '0', '1', ..."
        ),
    )
    system: PolicySystem = Field(
        default_factory=PolicySystem, description="System policy settings"
    )


class Certificate(BaseModel):
    """
    Certificate
    """

    ocspStapling: int = 3600
    oneTimeLoading: bool = False
    usage: str = "encipherment"
    buildChain: bool = False
    certificateFile: str = ""
    keyFile: str = ""
    certificate: List[str] = Field(default_factory=list)
    key: List[str] = Field(default_factory=list)


class TLSSettings(BaseModel):
    """ """

    serverName: str = Field(
        "", description="Specifies the domain of the server-side certificate"
    )
    rejectUnknownSni: bool = Field(
        False,
        description=(
            "When true, the server rejects TLS handshakes if the SNI received "
            "does not match domains specified in the certificate. "
        ),
    )
    allowInsecure: bool = Field(False)
    alpn: List[str] = Field(
        ["h2", "http/1.1"],
        description=(
            "An array of strings specifying the ALPN values used " "in TLS handshakes"
        ),
    )
    minVersion: str = Field("1.2")
    maxVersion: str = Field("1.3")
    cipherSuites: str = Field(
        "",
        description=(
            "Specifies a list of supported cryptographic suites, "
            "with names of each separated by a colon."
        ),
    )
    disableSystemRoot: bool = Field(
        False,
        description=(
            "Whether to disable the CA certificates provided by "
            "the operating system."
        ),
    )
    enableSessionResumption: bool = Field(
        False,
        description=(
            "When false, the session_ticket extension will not be "
            "included in ClientHello"
        ),
    )
    fingerprint: str = Field(
        "",
        description=("Specifies the fingerprint of the TLS Client Hello message"),
    )
    pinnedPeerCertificateChainSha256: List[str] = Field(
        default_factory=list,
        description=(
            "Specifies the SHA256 hash values of the certificate chain "
            "of the remote server, using the standard encoding format."
        ),
    )
    masterKeyLog: str = Field(
        "", description=("Path to the (Pre-)Master-Secret log file.")
    )
    certificates: List[Certificate] = Field(
        default_factory=list,
        description=(
            "A list of certificates, each representing a single certificate "
            "(fullchain recommended)."
        ),
    )


class TCPSettings(BaseModel):
    acceptProxyProtocol: bool = False
    header: Dict[str, str] = Field({"type": "none"})


class KCPSettings(BaseModel):
    pass


class WSSettings(BaseModel):
    acceptProxyProtocol: bool = False
    path: str = Field("/", description="HTTP path of the WebSocket")
    host: str = Field("", description="HTTP Host header sent by the client")
    headers: Dict[str, str] = Field(default_factory=dict)


class HttpSettings(BaseModel):
    pass


class GrpcSettings(BaseModel):
    pass


class HTTPUpgradeSettings(BaseModel):
    pass


class SplitHTTPSettings(BaseModel):
    pass


class ProxySettings(BaseModel):
    tag: str


class RealitySettings(BaseModel):
    show: bool = Field(False)
    dest: str | None = Field(None)
    xver: int = Field(0)
    serverName: str | None = Field(None)
    serverNames: List[str] = Field(default_factory=list)
    privateKey: str = Field("")
    minClientVer: str = Field("")
    maxClientVer: str = Field("")
    maxTimeDiff: int = Field(0)
    shortIds: List[str] = Field(default_factory=list)
    shortId: str | None = Field(None)
    fingerprint: str | None = Field(None)
    publicKey: str | None = Field(None)


class SockOpt(BaseModel):
    """ """

    mark: int = 0
    tcpFastOpen: bool = False
    tproxy: str = "off"
    domainStrategy: str = "AsIs"
    dialerProxy: str = ""
    acceptProxyProtocol: bool = False
    tcpKeepAliveInterval: int = 0
    tcpcongestion: str = "bbr"
    interface: str = "wg0"
    tcpMptcp: bool = False
    tcpNoDelay: bool = False


class StreamSettings(BaseModelConfig):
    """
    StreamSettings corresponds to the streamSettings property
    in the inbound or outbound config.
    Each inbound or outbound can be configured with different
    transports and can use streamSettings to specify local configs.
    """

    network: Network = Field(
        Network.tcp,
        description=(
            "The underlying protocol of the transport "
            "used by the data stream of the connection"
        ),
    )
    security: Security = Field(
        Security.none,
        description="Whether to enable transport layer encryption",
    )
    tlsSettings: TLSSettings | None = Field(None, description="Configures vanilla TLS")
    tcpSettings: TCPSettings | None = Field(None, description="Configures TCP")
    kcpSettings: KCPSettings | None = Field(default=None, description="Configures KCP")
    wsSettings: WSSettings | None = Field(None, description="Configures WebSocket")
    httpSettings: HttpSettings | None = Field(None, description="Configures HTTP")
    grpcSettings: GrpcSettings | None = Field(None, description="Configures gRPC")
    httpupgradeSettings: HTTPUpgradeSettings | None = Field(
        None, description="Configures HTTP"
    )
    splithttpSettings: SplitHTTPSettings | None = Field(
        None, description="Configures HTTP"
    )
    realitySettings: RealitySettings | None = Field(
        None, description="Configures Reality"
    )
    sockopt: SockOpt | None = Field(None)


class Sniffing(BaseModelConfig):
    enabled: bool = True
    destOverride: List[SniffingDest] = Field(
        default_factory=list,
        description=(
            "When the traffic is of a specified type, reset the destination "
            "of the current connection to the target address included "
            "in the list."
        ),
    )
    metadataOnly: bool = False
    domainsExcluded: List[str] = Field(
        default_factory=list, description="A list of domain names."
    )
    routeOnly: bool = False


class Allocate(BaseModel):
    strategy: str = "always"
    refresh: int = 5
    concurrency: int = 3


class Mux(BaseModel):
    enabled: bool = False
    concurrency: int = 8


class RoutingRule(BaseModelConfig):
    domainMatcher: DomainMatcher = Field(DomainMatcher.hybrid)
    type: str = "field"
    domain: List[str] = Field(default_factory=list)
    ip: List[str] = Field(default_factory=list)
    port: Optional[str] = Field(None, description="The target port range")
    sourcePort: Optional[str] = Field(None)
    network: Optional[NetworkRoutingRule] = Field(None)
    source: List[str] = Field(default_factory=list)
    user: List[str] = Field(default_factory=list)
    inboundTag: List[str] = Field(default_factory=list)
    protocol: List[InboundProtocol] = Field(default_factory=list)
    attrs: Dict[str, str] = Field(default_factory=dict)
    outboundTag: Optional[str] = Field(None)
    balancerTag: Optional[str] = Field(None)


class RoutingBalancer(BaseModelConfig):
    tag: str = Field("")
    selector: List[str] = Field(default_factory=list)
    fallbackTag: str = Field("")
    strategy: Dict[str, str] = Field(default_factory=dict)


class Routing(BaseModelConfig):
    domainStrategy: DomainStrategy = Field(
        DomainStrategy.AsIs, description="The domain name resolution strategy"
    )
    domainMatcher: DomainMatcher = Field(
        DomainMatcher.hybrid, description="The domain name matching algorithm"
    )
    rules: List[RoutingRule] = Field(default_factory=list)
    balancers: List[RoutingBalancer] = Field(default_factory=list)


class Inbound(BaseModelConfig):
    """
    Inbound connections are used to receive incoming data
    and the available protocols are listed in
    """

    _protocol_settings_map: ClassVar[
        dict[InboundProtocol, Type[ProtocolSettingsBase]]
    ] = {
        InboundProtocol.vless: ProtocolSettingsVless,
        InboundProtocol.dokodemo_door: ProtocolSettingsDokodemoDoor,
    }

    listen: str = Field(
        "0.0.0.0",
        description=(
            "The listening address, " "either an IP address or a Unix domain socket."
        ),
    )
    port: int | str = Field(1080, description="The listening port")
    # Fill from settings model
    protocol: InboundProtocol = Field(..., description="The connection protocol name")
    settings: Union[
        ProtocolSettingsBase, ProtocolSettingsVless, ProtocolSettingsDokodemoDoor
    ] = Field(
        default_factory=ProtocolSettingsBase,
        description=("The specific configuration content depends on the protocol"),
    )
    streamSettings: StreamSettings = Field(
        default_factory=StreamSettings,
        description=(
            "The underlying transport method is how the current Xray node "
            "interfaces with other nodes."
        ),
    )
    tag: str | None = Field(
        None,
        description=(
            "The identifier of this inbound connection, used to locate "
            "this connection in other configurations."
        ),
    )
    sniffing: Sniffing = Field(
        default_factory=Sniffing,
        description=(
            "Configures sniffing, which is used to determine the protocol "
            "of the current connection."
        ),
    )
    allocate: Allocate = Field(
        default_factory=Allocate,
        description=(
            "Specifies the specific settings for port allocation when "
            "multiple ports are set up"
        ),
    )

    @model_validator(mode="before")
    @classmethod
    def fill_protocol(cls, values: Dict[str, object]) -> Dict[str, object]:
        settings = values.get("settings", {})
        protocol = values.get("protocol")

        # Apply settings class based on protocol
        settings_class = cls._protocol_settings_map.get(protocol)
        if settings_class and isinstance(settings, dict):
            values["settings"] = settings_class(**settings)

        # Ensure protocol is consistent
        if isinstance(values.get("settings"), ProtocolSettingsBase):
            values["protocol"] = values["settings"].protocol.value
        elif isinstance(settings, dict):
            settings["protocol"] = protocol

        return values


class Outbound(BaseModelConfig):
    sendThrough: str = Field("0.0.0.0", description="The IP address used to send data.")
    protocol: InboundProtocol = Field(
        InboundProtocol.freedom, description="The connection protocol name"
    )
    settings: Dict = Field(default_factory=dict)
    tag: str | None = Field(
        None,
        description=(
            "The identifier of this inbound connection, used to locate "
            "this connection in other configurations."
        ),
    )
    streamSettings: StreamSettings | None = Field(
        None,
        description=(
            "The underlying transport method is how the current Xray node "
            "interfaces with other nodes."
        ),
    )
    proxySettings: ProxySettings | None = Field(
        None, description="The outbound proxy configuration."
    )
    mux: Mux | None = Field(
        None,
        description=(
            "The Mux feature distributes the data of multiple TCP connections "
            "on a single TCP connection."
        ),
    )


class XRayConfig(BaseModelConfig):
    """
    Full Xray server configuration.
    """

    stats: Optional[Stats] = Field(None, description="Enables statistics collection")
    api: Optional[Api] = Field(
        None, description="API interface configuration provides a set of APIs"
    )
    policy: Optional[Policy] = Field(
        None, description="Local policy can be used to set different policy settings"
    )
    log: Log = Field(default_factory=Log)
    routing: Routing = Field(
        default_factory=Routing,
        description=(
            "Configures routing. Specify rules to route connections "
            "through different outbounds."
        ),
    )
    inbounds: List[Inbound] = Field(
        default_factory=list,
        description=(
            "Inbound connections are used to receive incoming data "
            "and the available protocols are listed in"
        ),
    )
    outbounds: List[Outbound] = Field(
        default_factory=list,
        description=("An array of outbound connection configurations."),
    )

    @classmethod
    def from_config_file(cls, content: TextIO) -> XRayConfig:
        """
        Create a configuration object from JSON text.

        Args:
            content: Configuration file contents.
        """
        return cls.model_validate_json(content)

    def to_config_file(self, indent=None) -> str:
        """
        Return the configuration as a JSON string.
        """
        return self.model_dump_json(indent=indent, exclude_none=True)
