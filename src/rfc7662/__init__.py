"""RFC 7662 OAuth 2.0 Token Introspection models, validation, and serialization."""

from __future__ import annotations

import json
import urllib.parse
from datetime import datetime, timezone
from typing import Any, Mapping, Optional, Sequence, Union

__all__ = [
    "IntrospectionError",
    "IntrospectionRequest",
    "IntrospectionResponse",
]


class IntrospectionError(ValueError):
    """Base exception for RFC 7662 parsing and validation errors."""
    pass


class IntrospectionRequest:
    token: str
    token_type_hint: Optional[str]
    parameters: dict[str, str]

    def __init__(
        self,
        token: str,
        token_type_hint: Optional[str] = None,
        extra_parameters: Optional[Mapping[str, str]] = None,
    ) -> None:
        if not isinstance(token, str) or not token:
            raise IntrospectionError("token must be a non-empty string")
        self.token = token

        if token_type_hint is not None:
            if not isinstance(token_type_hint, str):
                raise IntrospectionError("token_type_hint must be a string")
            self.token_type_hint = token_type_hint
        else:
            self.token_type_hint = None

        self.parameters = {}
        if extra_parameters is not None:
            if not isinstance(extra_parameters, Mapping):
                raise IntrospectionError("extra_parameters must be a mapping of string keys and values")
            for k, v in extra_parameters.items():
                if not isinstance(k, str) or not isinstance(v, str):
                    raise IntrospectionError(f"extra parameter key and value must be strings: {k!r}={v!r}")
                if k in ("token", "token_type_hint"):
                    continue
                self.parameters[k] = v

    def to_urlencoded(self) -> str:
        """Serializes request to application/x-www-form-urlencoded format."""
        data = self.to_dict()
        return urllib.parse.urlencode(data)

    def to_dict(self) -> dict[str, str]:
        """Returns request fields as a dictionary of string parameters."""
        data: dict[str, str] = {"token": self.token}
        if self.token_type_hint is not None:
            data["token_type_hint"] = self.token_type_hint
        for k, v in self.parameters.items():
            if k not in data:
                data[k] = v
        return data

    @classmethod
    def from_urlencoded(cls, body: Union[str, bytes]) -> "IntrospectionRequest":
        """Parses and validates an application/x-www-form-urlencoded request body."""
        if isinstance(body, bytes):
            try:
                body = body.decode("utf-8")
            except UnicodeDecodeError as err:
                raise IntrospectionError(f"Invalid UTF-8 encoding in request body: {err}") from err
        elif not isinstance(body, str):
            raise IntrospectionError("Request body must be str or bytes")

        # parse_qs parses query parameters into lists of values
        parsed = urllib.parse.parse_qs(body, keep_blank_values=True)
        # flatten single values or validate
        flat_data: dict[str, str] = {}
        for k, vals in parsed.items():
            if vals:
                flat_data[k] = vals[0]
            else:
                flat_data[k] = ""

        return cls.from_dict(flat_data)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "IntrospectionRequest":
        """Parses and validates a request dictionary."""
        if not isinstance(data, Mapping):
            raise IntrospectionError("Request data must be a mapping")

        if "token" not in data:
            raise IntrospectionError("Missing required parameter: 'token'")

        token = data["token"]
        if not isinstance(token, str) or not token:
            raise IntrospectionError("'token' parameter must be a non-empty string")

        token_type_hint = data.get("token_type_hint")
        if token_type_hint is not None and not isinstance(token_type_hint, str):
            raise IntrospectionError("'token_type_hint' parameter must be a string")

        extra_parameters: dict[str, str] = {}
        for k, v in data.items():
            if k in ("token", "token_type_hint"):
                continue
            if not isinstance(k, str) or not isinstance(v, str):
                raise IntrospectionError(f"Custom parameter {k!r} and its value must be strings")
            extra_parameters[k] = v

        return cls(token=token, token_type_hint=token_type_hint, extra_parameters=extra_parameters)


_STANDARD_CLAIMS = {
    "active",
    "scope",
    "client_id",
    "username",
    "token_type",
    "exp",
    "iat",
    "nbf",
    "sub",
    "aud",
    "iss",
    "jti",
}


class IntrospectionResponse:
    active: bool
    scope: Optional[str]
    client_id: Optional[str]
    username: Optional[str]
    token_type: Optional[str]
    exp: Optional[int]
    iat: Optional[int]
    nbf: Optional[int]
    sub: Optional[str]
    aud: Optional[Union[str, list[str]]]
    iss: Optional[str]
    jti: Optional[str]
    extra_claims: dict[str, Any]

    def __init__(
        self,
        active: bool,
        scope: Optional[str] = None,
        client_id: Optional[str] = None,
        username: Optional[str] = None,
        token_type: Optional[str] = None,
        exp: Optional[int] = None,
        iat: Optional[int] = None,
        nbf: Optional[int] = None,
        sub: Optional[str] = None,
        aud: Optional[Union[str, Sequence[str]]] = None,
        iss: Optional[str] = None,
        jti: Optional[str] = None,
        extra_claims: Optional[Mapping[str, Any]] = None,
    ) -> None:
        if type(active) is not bool:
            raise IntrospectionError(f"'active' must be a boolean, got {type(active).__name__}")
        self.active = active

        for name, val in [
            ("scope", scope),
            ("client_id", client_id),
            ("username", username),
            ("token_type", token_type),
            ("sub", sub),
            ("iss", iss),
            ("jti", jti),
        ]:
            if val is not None and not isinstance(val, str):
                raise IntrospectionError(f"'{name}' claim must be a string or None")

        self.scope = scope
        self.client_id = client_id
        self.username = username
        self.token_type = token_type
        self.sub = sub
        self.iss = iss
        self.jti = jti

        for name, val in [("exp", exp), ("iat", iat), ("nbf", nbf)]:
            if val is not None:
                if type(val) is not int or isinstance(val, bool):
                    raise IntrospectionError(f"'{name}' claim must be an integer timestamp (seconds since epoch)")

        self.exp = exp
        self.iat = iat
        self.nbf = nbf

        if aud is not None:
            if isinstance(aud, str):
                self.aud = aud
            elif isinstance(aud, Sequence) and not isinstance(aud, (bytes, bytearray)):
                for item in aud:
                    if not isinstance(item, str):
                        raise IntrospectionError("All elements in 'aud' sequence must be strings")
                self.aud = list(aud)
            else:
                raise IntrospectionError("'aud' claim must be a string or sequence of strings")
        else:
            self.aud = None

        self.extra_claims = {}
        if extra_claims is not None:
            if not isinstance(extra_claims, Mapping):
                raise IntrospectionError("extra_claims must be a mapping")
            for k, v in extra_claims.items():
                if not isinstance(k, str):
                    raise IntrospectionError("claim names must be strings")
                if k in _STANDARD_CLAIMS:
                    continue
                self.extra_claims[k] = v

    @property
    def scopes(self) -> frozenset[str]:
        """Returns the scope member split into a frozenset of scope strings."""
        if not self.scope:
            return frozenset()
        return frozenset(self.scope.split())

    @property
    def exp_datetime(self) -> Optional[datetime]:
        """Returns exp as a UTC datetime if present."""
        if self.exp is None:
            return None
        return datetime.fromtimestamp(self.exp, tz=timezone.utc)

    @property
    def iat_datetime(self) -> Optional[datetime]:
        """Returns iat as a UTC datetime if present."""
        if self.iat is None:
            return None
        return datetime.fromtimestamp(self.iat, tz=timezone.utc)

    @property
    def nbf_datetime(self) -> Optional[datetime]:
        """Returns nbf as a UTC datetime if present."""
        if self.nbf is None:
            return None
        return datetime.fromtimestamp(self.nbf, tz=timezone.utc)

    def to_dict(self) -> dict[str, Any]:
        """Serializes response to a clean dictionary omitting None standard claims."""
        result: dict[str, Any] = {"active": self.active}
        if self.scope is not None:
            result["scope"] = self.scope
        if self.client_id is not None:
            result["client_id"] = self.client_id
        if self.username is not None:
            result["username"] = self.username
        if self.token_type is not None:
            result["token_type"] = self.token_type
        if self.exp is not None:
            result["exp"] = self.exp
        if self.iat is not None:
            result["iat"] = self.iat
        if self.nbf is not None:
            result["nbf"] = self.nbf
        if self.sub is not None:
            result["sub"] = self.sub
        if self.aud is not None:
            result["aud"] = self.aud
        if self.iss is not None:
            result["iss"] = self.iss
        if self.jti is not None:
            result["jti"] = self.jti

        for k, v in self.extra_claims.items():
            if k not in result:
                result[k] = v

        return result

    def to_json(self) -> str:
        """Serializes response to RFC-compliant JSON string."""
        return json.dumps(self.to_dict())

    @classmethod
    def from_json(cls, payload: Union[str, bytes]) -> "IntrospectionResponse":
        """Parses and validates an application/json string or bytes payload."""
        if isinstance(payload, bytes):
            try:
                payload = payload.decode("utf-8")
            except UnicodeDecodeError as err:
                raise IntrospectionError(f"Invalid UTF-8 encoding in JSON payload: {err}") from err
        elif not isinstance(payload, str):
            raise IntrospectionError("Payload must be a string or bytes")

        try:
            data = json.loads(payload)
        except json.JSONDecodeError as err:
            raise IntrospectionError(f"Malformed JSON response: {err}") from err

        if not isinstance(data, Mapping):
            raise IntrospectionError("JSON response root must be a JSON object")

        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "IntrospectionResponse":
        """Parses and validates a dictionary into an IntrospectionResponse object."""
        if not isinstance(data, Mapping):
            raise IntrospectionError("Response data must be a mapping")

        if "active" not in data:
            raise IntrospectionError("Missing required member: 'active'")

        active = data["active"]
        if type(active) is not bool:
            raise IntrospectionError(f"'active' member must be a boolean, got {type(active).__name__}")

        scope = data.get("scope")
        client_id = data.get("client_id")
        username = data.get("username")
        token_type = data.get("token_type")
        exp = data.get("exp")
        iat = data.get("iat")
        nbf = data.get("nbf")
        sub = data.get("sub")
        aud = data.get("aud")
        iss = data.get("iss")
        jti = data.get("jti")

        extra_claims: dict[str, Any] = {}
        for k, v in data.items():
            if k not in _STANDARD_CLAIMS:
                extra_claims[k] = v

        return cls(
            active=active,
            scope=scope,
            client_id=client_id,
            username=username,
            token_type=token_type,
            exp=exp,
            iat=iat,
            nbf=nbf,
            sub=sub,
            aud=aud,
            iss=iss,
            jti=jti,
            extra_claims=extra_claims,
        )
