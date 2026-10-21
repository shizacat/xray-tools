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

from pathlib import Path
from typing import List, Optional

from pydantic import Field

from .base import BaseModelConfig
from .models import Api, Inbound, Log, Outbound, Policy, Routing, Stats


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
    def from_config(cls, config: str) -> XRayConfig:
        """
        Create a configuration object from a JSON string.

        Args:
            config: Configuration as a JSON string.
        """
        return cls.model_validate_json(config)

    @classmethod
    def from_config_file(cls, path: str | Path) -> XRayConfig:
        """
        Create a configuration object by reading a JSON file.

        Args:
            path: Path to the configuration file.
        """
        return cls.from_config(Path(path).read_text(encoding="utf-8"))

    def to_config(self, indent=None) -> str:
        """
        Return the configuration as a JSON string.

        Fields whose value is ``None`` are omitted.
        """
        return self.model_dump_json(indent=indent, exclude_none=True)

    def to_config_file(self, path: str | Path, indent=None) -> None:
        """
        Write the configuration to a JSON file.

        Args:
            path: Path to the configuration file.
            indent: JSON indentation, forwarded to ``to_config``.
        """
        Path(path).write_text(self.to_config(indent=indent), encoding="utf-8")
