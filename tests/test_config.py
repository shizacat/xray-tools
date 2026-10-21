import json

import pytest
from pytest import fixture
from pydantic import ValidationError

from xray_tools import config
from xray_tools import config as xray_config
from xray_tools import protocols


# --- Fixture ---

@fixture
def xray_config_ex1() -> xray_config.XRayConfig:
    return config.XRayConfig.from_config_file("""
        {
            "log": {"loglevel": "error"},
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
            ]
        }
    """)


# --- Tests ---


def test_create_empty_config():
    obj = config.XRayConfig()

    # get config
    c = obj.to_config_file()
    assert isinstance(c, str)

    # get config with indent
    c = obj.to_config_file(indent=4)
    assert isinstance(c, str)


def test_config_create_from_file(xray_config_ex1: xray_config.XRayConfig):
    """
    Check type of config
    """
    assert isinstance(xray_config_ex1, config.XRayConfig)
    assert isinstance(
        xray_config_ex1.inbounds[0].settings, protocols.ProtocolSettingsVless)


def test_config_to_config_file(xray_config_ex1: xray_config.XRayConfig):
    """
    Check as create dump
    """
    dump = xray_config_ex1.to_config_file()
    assert isinstance(dump, str)
    dump_dict = json.loads(dump)
    assert len(dump_dict["inbounds"][0]["settings"]["clients"]) == 1
    assert dump_dict["inbounds"][0]["settings"]["decryption"] == "none"


def test_config_create_fill_01():
    """
    Создаем и заполняем конфиг
    """
    config = xray_config.XRayConfig(
        inbounds=[
            xray_config.Inbound(
                settings=protocols.ProtocolSettingsVless(),
            )
        ]
    )
    config.inbounds[0].settings.client_add(email="test@test.ru")
    assert isinstance(config.to_config_file(), str)


def test_log_crete_default():
    r = config.Log()
    assert isinstance(r, config.Log)


def test_stream_settings():
    r = config.StreamSettings()
    assert isinstance(r, config.StreamSettings)


def test_inbound():
    r = config.Inbound(settings=protocols.ProtocolSettingsVless())
    assert isinstance(r, config.Inbound)
    assert r.protocol == protocols.InboundProtocol.vless


def test_outbound():
    r = config.Outbound()
    assert isinstance(r, config.Outbound)


def test_stats():
    r = xray_config.Stats()
    assert isinstance(r, xray_config.Stats)

    # Проверяем, что stats добавился как пустой словарь
    obj = config.XRayConfig(stats=xray_config.Stats())
    cfg = json.loads(obj.to_config_file())
    assert cfg["stats"] == {}

    # Check, that stats is not included in config
    obj = config.XRayConfig()
    cfg = json.loads(obj.to_config_file())
    assert "stats" not in cfg


def test_api():
    r = xray_config.Api(tag="api")
    assert isinstance(r, xray_config.Api)

    # Проверяем, что api не включен в config
    obj = config.XRayConfig()
    cfg = json.loads(obj.to_config_file())
    assert "api" not in cfg

    # Проверяем, что api добавился в config
    obj = config.XRayConfig(
        api=xray_config.Api(
            tag="api",
            services=[xray_config.ApiService.StatsService]
        )
    )
    cfg = json.loads(obj.to_config_file())
    assert cfg["api"]["tag"] == "api"


def test_policy():
    r = xray_config.Policy()
    assert isinstance(r, xray_config.Policy)

    # Check level key format, raise ValidationError
    with pytest.raises(ValidationError):
        xray_config.Policy(levels={"test": {}})

    # Check level key correct format
    r = xray_config.Policy(levels={"0": xray_config.PolicyLevel()})
    assert isinstance(r, xray_config.Policy)

    # Проверяем, что policy не включен в config
    obj = config.XRayConfig()
    cfg = json.loads(obj.to_config_file())
    assert "policy" not in cfg

    # Проверяем, что policy добавился в config
    obj = config.XRayConfig(
        policy=xray_config.Policy(
            levels={
                "0": xray_config.PolicyLevel(
                    statsUserUplink=True,
                )
            }
        )
    )
    cfg = json.loads(obj.to_config_file())
    assert cfg["policy"]["levels"]["0"]["statsUserUplink"] is True


def test_ws_settings_roundtrip():
    """path/host у WebSocket не теряются при разборе и сборке конфига."""
    import json as _json
    from xray_tools.config import XRayConfig as _XRayConfig

    raw = {
        "inbounds": [{
            "listen": "127.0.0.1", "port": 10443, "protocol": "vless",
            "settings": {"clients": [], "decryption": "none"},
            "streamSettings": {
                "network": "ws", "security": "none",
                "wsSettings": {"path": "/media/stream/abc",
                               "host": "cloud.example.org"},
            },
        }],
    }
    cfg = _XRayConfig.model_validate_json(_json.dumps(raw))
    out = _json.loads(cfg.to_config_file())
    ws = out["inbounds"][0]["streamSettings"]["wsSettings"]
    assert ws["path"] == "/media/stream/abc"
    assert ws["host"] == "cloud.example.org"
