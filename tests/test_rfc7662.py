import pytest
from datetime import datetime, timezone
from rfc7662 import IntrospectionError, IntrospectionRequest, IntrospectionResponse


def test_parse_valid_urlencoded_request_with_token_and_hint():
    body = "token=mF_9.B5f-4.1JqM&token_type_hint=access_token"
    req = IntrospectionRequest.from_urlencoded(body)
    assert req.token == "mF_9.B5f-4.1JqM"
    assert req.token_type_hint == "access_token"
    assert req.parameters == {}

    # Also test bytes input
    req_bytes = IntrospectionRequest.from_urlencoded(body.encode("utf-8"))
    assert req_bytes.token == "mF_9.B5f-4.1JqM"
    assert req_bytes.token_type_hint == "access_token"


def test_parse_urlencoded_request_missing_token_raises_error():
    body = "token_type_hint=access_token"
    with pytest.raises(IntrospectionError, match="Missing required parameter: 'token'"):
        IntrospectionRequest.from_urlencoded(body)

    # Empty token value
    with pytest.raises(IntrospectionError):
        IntrospectionRequest.from_urlencoded("token=")
def test_oliva_rfc7662_import():
    import oliva_rfc7662
    assert oliva_rfc7662.IntrospectionRequest is IntrospectionRequest
    assert oliva_rfc7662.IntrospectionResponse is IntrospectionResponse
    assert oliva_rfc7662.IntrospectionError is IntrospectionError




def test_parse_urlencoded_request_with_custom_extension_parameters():
    body = "token=xyz123&custom_param=foo&resource=https%3A%2F%2Fapi.example.com"
    req = IntrospectionRequest.from_urlencoded(body)
    assert req.token == "xyz123"
    assert req.token_type_hint is None
    assert req.parameters == {
        "custom_param": "foo",
        "resource": "https://api.example.com",
    }


def test_serialize_request_to_urlencoded():
    req = IntrospectionRequest(
        token="secret-token-123",
        token_type_hint="refresh_token",
        extra_parameters={"client_id": "client_abc"},
    )
    urlencoded = req.to_urlencoded()
    parsed = IntrospectionRequest.from_urlencoded(urlencoded)
    assert parsed.token == "secret-token-123"
    assert parsed.token_type_hint == "refresh_token"
    assert parsed.parameters == {"client_id": "client_abc"}


def test_serialize_request_to_dict():
    req = IntrospectionRequest(
        token="tok1",
        token_type_hint="access_token",
        extra_parameters={"extra": "val"},
    )
    d = req.to_dict()
    assert d == {
        "token": "tok1",
        "token_type_hint": "access_token",
        "extra": "val",
    }

    # Without hint
    req_no_hint = IntrospectionRequest(token="tok2")
    assert req_no_hint.to_dict() == {"token": "tok2"}


def test_parse_valid_active_response_with_all_standard_claims():
    payload = {
        "active": True,
        "scope": "read write admin",
        "client_id": "l238j32",
        "username": "jdoe",
        "token_type": "Bearer",
        "exp": 1419356238,
        "iat": 1419350238,
        "nbf": 1419350200,
        "sub": "Z5O3upPC88QrAjx00dis",
        "aud": "https://protected.example.net/resource",
        "iss": "https://server.example.com/",
        "jti": "b8ge2wb5-5ef2-4bc9-93ef-2a78f3e58fa2",
    }
    resp = IntrospectionResponse.from_dict(payload)
    assert resp.active is True
    assert resp.scope == "read write admin"
    assert resp.client_id == "l238j32"
    assert resp.username == "jdoe"
    assert resp.token_type == "Bearer"
    assert resp.exp == 1419356238
    assert resp.iat == 1419350238
    assert resp.nbf == 1419350200
    assert resp.sub == "Z5O3upPC88QrAjx00dis"
    assert resp.aud == "https://protected.example.net/resource"
    assert resp.iss == "https://server.example.com/"
    assert resp.jti == "b8ge2wb5-5ef2-4bc9-93ef-2a78f3e58fa2"
    assert resp.extra_claims == {}


def test_parse_valid_inactive_response_minimal():
    payload = '{"active": false}'
    resp = IntrospectionResponse.from_json(payload)
    assert resp.active is False
    assert resp.scope is None
    assert resp.client_id is None
    assert resp.username is None
    assert resp.token_type is None
    assert resp.exp is None
    assert resp.iat is None
    assert resp.nbf is None
    assert resp.sub is None
    assert resp.aud is None
    assert resp.iss is None
    assert resp.jti is None
    assert resp.extra_claims == {}
    assert resp.to_dict() == {"active": False}


def test_parse_response_missing_active_field_raises_error():
    with pytest.raises(IntrospectionError, match="Missing required member: 'active'"):
        IntrospectionResponse.from_dict({"scope": "read"})

    with pytest.raises(IntrospectionError, match="Missing required member: 'active'"):
        IntrospectionResponse.from_json('{"scope": "read"}')


def test_parse_response_invalid_active_type_raises_error():
    with pytest.raises(IntrospectionError, match="'active' member must be a boolean"):
        IntrospectionResponse.from_dict({"active": "true"})

    with pytest.raises(IntrospectionError, match="'active' member must be a boolean"):
        IntrospectionResponse.from_dict({"active": 1})

    with pytest.raises(IntrospectionError):
        IntrospectionResponse(active="yes")  # type: ignore


def test_parse_response_invalid_timestamp_types_raise_error():
    with pytest.raises(IntrospectionError, match="'exp' claim must be an integer timestamp"):
        IntrospectionResponse.from_dict({"active": True, "exp": "1419356238"})

    with pytest.raises(IntrospectionError, match="'exp' claim must be an integer timestamp"):
        IntrospectionResponse.from_dict({"active": True, "exp": 1419356238.5})

    with pytest.raises(IntrospectionError, match="'exp' claim must be an integer timestamp"):
        IntrospectionResponse.from_dict({"active": True, "exp": True})

    with pytest.raises(IntrospectionError, match="'iat' claim must be an integer timestamp"):
        IntrospectionResponse.from_dict({"active": True, "iat": "now"})

    with pytest.raises(IntrospectionError, match="'nbf' claim must be an integer timestamp"):
        IntrospectionResponse.from_dict({"active": True, "nbf": [123]})


def test_parse_response_aud_as_string_and_list_of_strings():
    resp_str = IntrospectionResponse.from_dict({
        "active": True,
        "aud": "https://api.example.com",
    })
    assert resp_str.aud == "https://api.example.com"

    resp_list = IntrospectionResponse.from_dict({
        "active": True,
        "aud": ["https://api.example.com", "https://service.example.com"],
    })
    assert resp_list.aud == ["https://api.example.com", "https://service.example.com"]

    # Tuple passed to constructor
    resp_tuple = IntrospectionResponse(active=True, aud=("aud1", "aud2"))
    assert resp_tuple.aud == ["aud1", "aud2"]


def test_parse_response_invalid_aud_type_raises_error():
    with pytest.raises(IntrospectionError, match="'aud' claim must be a string or sequence of strings"):
        IntrospectionResponse.from_dict({"active": True, "aud": 12345})

    with pytest.raises(IntrospectionError, match="All elements in 'aud' sequence must be strings"):
        IntrospectionResponse.from_dict({"active": True, "aud": ["valid", 123]})

    with pytest.raises(IntrospectionError, match="'aud' claim must be a string or sequence of strings"):
        IntrospectionResponse.from_dict({"active": True, "aud": {"aud": "foo"}})


def test_parse_response_with_custom_extension_claims():
    payload = {
        "active": True,
        "scope": "read",
        "custom_str": "hello",
        "custom_int": 42,
        "custom_obj": {"key": "val"},
        "custom_list": [1, 2, 3],
    }
    resp = IntrospectionResponse.from_dict(payload)
    assert resp.active is True
    assert resp.scope == "read"
    assert resp.extra_claims == {
        "custom_str": "hello",
        "custom_int": 42,
        "custom_obj": {"key": "val"},
        "custom_list": [1, 2, 3],
    }

    serialized = resp.to_dict()
    assert serialized["custom_str"] == "hello"
    assert serialized["custom_int"] == 42
    assert serialized["custom_obj"] == {"key": "val"}
    assert serialized["custom_list"] == [1, 2, 3]


def test_response_scopes_property_parses_space_delimited_string():
    resp = IntrospectionResponse(active=True, scope="read write   delete")
    assert resp.scopes == frozenset({"read", "write", "delete"})

    resp_empty = IntrospectionResponse(active=True, scope="")
    assert resp_empty.scopes == frozenset()

    resp_none = IntrospectionResponse(active=True, scope=None)
    assert resp_none.scopes == frozenset()


def test_response_datetime_properties_convert_epoch_to_utc():
    resp = IntrospectionResponse(
        active=True,
        exp=1419356238,
        iat=1419350238,
        nbf=1419350200,
    )
    assert resp.exp_datetime == datetime.fromtimestamp(1419356238, tz=timezone.utc)
    assert resp.iat_datetime == datetime.fromtimestamp(1419350238, tz=timezone.utc)
    assert resp.nbf_datetime == datetime.fromtimestamp(1419350200, tz=timezone.utc)
    assert resp.exp_datetime.tzinfo == timezone.utc

    resp_none = IntrospectionResponse(active=True)
    assert resp_none.exp_datetime is None
    assert resp_none.iat_datetime is None
    assert resp_none.nbf_datetime is None


def test_response_to_dict_omits_none_standard_claims():
    resp = IntrospectionResponse(
        active=True,
        scope="read",
        extra_claims={"org_id": "12345"},
    )
    d = resp.to_dict()
    assert d == {
        "active": True,
        "scope": "read",
        "org_id": "12345",
    }
    # Standard claims with None must NOT be present
    for standard_claim in [
        "client_id", "username", "token_type", "exp", "iat", "nbf", "sub", "aud", "iss", "jti"
    ]:
        assert standard_claim not in d


def test_response_to_json_and_roundtrip_equivalence():
    original = IntrospectionResponse(
        active=True,
        scope="read write",
        client_id="client123",
        username="alice",
        token_type="Bearer",
        exp=1700000000,
        iat=1699990000,
        nbf=1699990000,
        sub="user_1",
        aud=["aud1", "aud2"],
        iss="https://auth.example.com",
        jti="uuid-1234",
        extra_claims={"role": "admin", "groups": ["engineering", "security"]},
    )

    json_str = original.to_json()
    roundtripped = IntrospectionResponse.from_json(json_str)

    assert roundtripped.active == original.active
    assert roundtripped.scope == original.scope
    assert roundtripped.client_id == original.client_id
    assert roundtripped.username == original.username
    assert roundtripped.token_type == original.token_type
    assert roundtripped.exp == original.exp
    assert roundtripped.iat == original.iat
    assert roundtripped.nbf == original.nbf
    assert roundtripped.sub == original.sub
    assert roundtripped.aud == original.aud
    assert roundtripped.iss == original.iss
    assert roundtripped.jti == original.jti
    assert roundtripped.extra_claims == original.extra_claims

    # Also test from_json with bytes
    roundtripped_bytes = IntrospectionResponse.from_json(json_str.encode("utf-8"))
    assert roundtripped_bytes.to_dict() == original.to_dict()


def test_malformed_json_response_raises_introspection_error():
    with pytest.raises(IntrospectionError, match="Malformed JSON response"):
        IntrospectionResponse.from_json("{invalid json")

    with pytest.raises(IntrospectionError, match="JSON response root must be a JSON object"):
        IntrospectionResponse.from_json("[]")

    with pytest.raises(IntrospectionError, match="JSON response root must be a JSON object"):
        IntrospectionResponse.from_json('"string"')
