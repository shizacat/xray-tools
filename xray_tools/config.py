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

from typing import List, Optional, TextIO

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
