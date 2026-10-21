"""
Describe diffent protocols
"""

from __future__ import annotations

import uuid
from enum import Enum
from typing import Optional, List, Dict

from pydantic import BaseModel, Field

from .base import BaseModelConfig


def gen_uuid() -> str:
    return str(uuid.uuid4())


class InboundProtocol(str, Enum):
    """
    Inbound connections are used to receive incoming data
    and the available protocols are listed in
    """

    tcp = "tcp"
    kcp = "kcp"
    ws = "ws"
    h2 = "h2"
    quic = "quic"
    grpc = "grpc"
    dokodemo = "dokodemo"
    dokodemo_door = "dokodemo-door"
    freedom = "freedom"
    blackhole = "blackhole"
    socks = "socks"
    http = "http"
    mtproto = "mtproto"
    tuic = "tuic"
    vless = "vless"
    vmess = "vmess"
    trojan = "trojan"
    shadowsocks = "shadowsocks"
    reality = "reality"
    wireguard = "wireguard"


class ProtocolSettingsBase(BaseModelConfig, BaseModel):
    """
    Base class for protocol settings
    """

    protocol: InboundProtocol = Field(..., exclude=True, description="Protocol")

    def client_add(self, client_id: Optional[str] = None, **kwargs):
        """
        Add a client to the protocol
        """
        raise NotImplementedError()

    def client_remove(self, client_id: str):
        """
        Remove a client from the protocol
        """
        raise NotImplementedError()


class VlessSettingFlow(str, Enum):
    xtls_rprx_vision = "xtls-rprx-vision"


class ClientVless(BaseModelConfig):
    id: str = Field(default_factory=gen_uuid, description="Unique ID of the client")
    level: int = Field(0, description="Level of the client")
    email: str = Field(..., description="Email of the client")
    flow: Optional[VlessSettingFlow] = Field(
        None, description="Flow control mode used to select the XTLS algorithm"
    )

    def __eq__(self, other: ClientVless):
        if not isinstance(other, ClientVless):
            return NotImplemented
        return self.id == other.id and self.email == other.email


class ProtocolSettingsVless(ProtocolSettingsBase):
    protocol: InboundProtocol = Field(InboundProtocol.vless, exclude=True)

    clients: List[ClientVless] = Field(
        default_factory=list, description="List of clients"
    )
    decryption: str = Field("none", description="Decryption method")
    fallbacks: List[Dict] = Field(
        default_factory=list,
        description=(
            "An array that contains a series of powerful fallback " "configurations"
        ),
    )

    def client_add(self, client_id: Optional[str] = None, **kwargs):
        """
        Add a client to the protocol
        """
        if client_id is not None:
            kwargs["id"] = client_id
        client = ClientVless(**kwargs)
        if client not in self.clients:
            self.clients.append(client)
        return client

    def client_remove(self, client_id: str):
        """
        Remove a client from the protocol
        """
        self.clients = [client for client in self.clients if client.id != client_id]


class ProtocolSettingsDokodemoDoor(ProtocolSettingsBase):
    protocol: InboundProtocol = Field(InboundProtocol.dokodemo_door, exclude=True)

    address: str = Field(..., description="Address to bind to")
