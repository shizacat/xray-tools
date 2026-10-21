import json

import pytest
from pytest import fixture
from pydantic import ValidationError

from xray_tools import config
from xray_tools import enums
from xray_tools import models
from xray_tools import protocols


# --- Fixture ---

@fixture
def xray_config_ex1() -> config.XRayConfig:
    return config.XRayConfig.from_config("""
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
    c = obj.to_config()
    assert isinstance(c, str)

    # get config with indent
    c = obj.to_config(indent=4)
    assert isinstance(c, str)


def test_config_create_from_file(xray_config_ex1: config.XRayConfig):
    """
    Check type of config
    """
    assert isinstance(xray_config_ex1, config.XRayConfig)
    assert isinstance(
        xray_config_ex1.inbounds[0].settings, protocols.ProtocolSettingsVless)


def test_from_config_file(tmp_path, xray_config_ex1: config.XRayConfig):
    path = tmp_path / "config.json"
    xray_config_ex1.to_config_file(path)

    loaded = config.XRayConfig.from_config_file(path)

    assert loaded.inbounds[0].tag == "vless_tls"
    assert isinstance(loaded.inbounds[0].settings, protocols.ProtocolSettingsVless)


def test_config_to_config_file(xray_config_ex1: config.XRayConfig):
    """
    Check as create dump
    """
    dump = xray_config_ex1.to_config()
    assert isinstance(dump, str)
    dump_dict = json.loads(dump)
    assert len(dump_dict["inbounds"][0]["settings"]["clients"]) == 1
    assert dump_dict["inbounds"][0]["settings"]["decryption"] == "none"


def test_config_create_fill_01():
    """
    Создаем и заполняем конфиг
    """
    cfg = config.XRayConfig(
        inbounds=[
            models.Inbound(
                settings=protocols.ProtocolSettingsVless(),
            )
        ]
    )
    cfg.inbounds[0].settings.client_add(email="test@test.ru")
    assert isinstance(cfg.to_config(), str)


def test_log_crete_default():
    r = models.Log()
    assert isinstance(r, models.Log)


def test_stream_settings():
    r = models.StreamSettings()
    assert isinstance(r, models.StreamSettings)


def test_inbound():
    r = models.Inbound(settings=protocols.ProtocolSettingsVless())
    assert isinstance(r, models.Inbound)
    assert r.protocol == protocols.InboundProtocol.vless


def test_outbound():
    r = models.Outbound()
    assert isinstance(r, models.Outbound)


def test_stats():
    r = models.Stats()
    assert isinstance(r, models.Stats)

    # Проверяем, что stats добавился как пустой словарь
    obj = config.XRayConfig(stats=models.Stats())
    cfg = json.loads(obj.to_config())
    assert cfg["stats"] == {}

    # Check, that stats is not included in config
    obj = config.XRayConfig()
    cfg = json.loads(obj.to_config())
    assert "stats" not in cfg


def test_api():
    r = models.Api(tag="api")
    assert isinstance(r, models.Api)

    # Проверяем, что api не включен в config
    obj = config.XRayConfig()
    cfg = json.loads(obj.to_config())
    assert "api" not in cfg

    # Проверяем, что api добавился в config
    obj = config.XRayConfig(
        api=models.Api(
            tag="api",
            services=[enums.ApiService.StatsService]
        )
    )
    cfg = json.loads(obj.to_config())
    assert cfg["api"]["tag"] == "api"


def test_policy():
    r = models.Policy()
    assert isinstance(r, models.Policy)

    # Check level key format, raise ValidationError
    with pytest.raises(ValidationError):
        models.Policy(levels={"test": {}})

    # Check level key correct format
    r = models.Policy(levels={"0": models.PolicyLevel()})
    assert isinstance(r, models.Policy)

    # Проверяем, что policy не включен в config
    obj = config.XRayConfig()
    cfg = json.loads(obj.to_config())
    assert "policy" not in cfg

    # Проверяем, что policy добавился в config
    obj = config.XRayConfig(
        policy=models.Policy(
            levels={
                "0": models.PolicyLevel(
                    statsUserUplink=True,
                )
            }
        )
    )
    cfg = json.loads(obj.to_config())
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
    out = _json.loads(cfg.to_config())
    ws = out["inbounds"][0]["streamSettings"]["wsSettings"]
    assert ws["path"] == "/media/stream/abc"
    assert ws["host"] == "cloud.example.org"
