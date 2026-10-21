from xray_tools import protocols


def test_protocol_vless_add_remove_client():
    obj = protocols.ProtocolSettingsVless()

    # Add
    c = obj.client_add(email="test@example.com")
    assert len(obj.clients) == 1
    assert isinstance(c, protocols.ClientVless)
    assert c == obj.clients[0]

    # Remove
    obj.client_remove(c.id)
    assert len(obj.clients) == 0


def test_protocol_vless_add_client_more_than_one():
    """При повторном добавлении клиента не добавлять его
    при этом не должно быть исключения
    """
    obj = protocols.ProtocolSettingsVless()

    # Add
    c = obj.client_add(client_id="test", email="test@example.com")
    c = obj.client_add(client_id="test", email="test@example.com")
    c = obj.client_add(client_id="test", email="test@example.com")
    assert isinstance(c, protocols.ClientVless)
    assert len(obj.clients) == 1
    assert c == obj.clients[0]
