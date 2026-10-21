# Xray tools — Python library

Create and manage [Xray-core](https://github.com/XTLS/Xray-core) configuration: inbounds, outbounds, routing and protocol settings. Pure Python implementation.

Links:
- https://github.com/XTLS/Xray-core
- https://xtls.github.io/config/

## Install

Requires Python 3.10 or newer.

```bash
pip install xray-tools
```

## Usage

The root object is `XRayConfig`, imported from `xray_tools`. Nested sections live in `xray_tools.models`, and enums such as `LogLevel` and `Network` live in `xray_tools.enums`. Field names match the [Xray JSON config](https://xtls.github.io/config/).

VLESS and dokodemo-door have typed `settings`. VLESS clients are added and removed through `ProtocolSettingsVless`.

### Read and write

`from_config()` builds a config from a JSON string, and `to_config()` returns one. `from_config_file()` and `to_config_file()` read and write a JSON file. Fields whose value is `None` are omitted.

```python
from xray_tools import XRayConfig

config = XRayConfig.from_config_file("config.json")
config.inbounds[0].settings.client_add(email="next@example.com")
config.to_config_file("config.json", indent=2)
```

### Build a config

```python
from xray_tools import XRayConfig
from xray_tools.enums import LogLevel, Network, Security, SniffingDest
from xray_tools.models import (
    Inbound,
    Log,
    Outbound,
    RealitySettings,
    Routing,
    RoutingRule,
    Sniffing,
    StreamSettings,
)
from xray_tools.protocols import InboundProtocol, ProtocolSettingsVless

clients = ProtocolSettingsVless()
client = clients.client_add(email="user@example.com", flow="xtls-rprx-vision")

config = XRayConfig(
    log=Log(loglevel=LogLevel.warning),
    inbounds=[
        Inbound(
            port=443,
            tag="vless-in",
            settings=clients,
            streamSettings=StreamSettings(
                network=Network.tcp,
                security=Security.reality,
                realitySettings=RealitySettings(
                    dest="www.microsoft.com:443",
                    serverNames=["www.microsoft.com"],
                    privateKey="<private key>",
                    shortIds=["<short id>"],
                ),
            ),
            sniffing=Sniffing(destOverride=[SniffingDest.http, SniffingDest.tls]),
        )
    ],
    outbounds=[
        Outbound(protocol=InboundProtocol.freedom, tag="direct"),
        Outbound(protocol=InboundProtocol.blackhole, tag="block"),
    ],
    routing=Routing(
        rules=[
            RoutingRule(domain=["geosite:category-ads-all"], outboundTag="block"),
            RoutingRule(network="tcp,udp", outboundTag="direct"),
        ]
    ),
)

print(client.id)
print(config.to_config(indent=2))
```

`client_add` generates a UUID when `client_id` is omitted. The same client (same id and email) is not added twice. `client_remove(client_id)` deletes by id.

## Development

Run tests:

```bash
pytest
```
