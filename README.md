# lab-rfc7662-py

A zero-dependency Python 3.10+ library providing strictly typed models, validation, and serialization for RFC 7662 OAuth 2.0 Token Introspection request and response bodies.

## Overview

RFC 7662 specifies a method for a protected resource to query an OAuth 2.0 authorization server to determine the active state and meta-information of an OAuth 2.0 token.

`lab-rfc7662-py` provides:
- **Zero external dependencies**: Built entirely on standard library (`typing`, `urllib.parse`, `json`, `datetime`).
- **Strict typing**: Python 3.10+ type annotations (`py.typed` marker included).
- **RFC 7662 Compliant**:
  - Request parsing and serialization (`application/x-www-form-urlencoded`).
  - Response parsing and serialization (`application/json`).
  - Standard claim validation (`active`, `scope`, `client_id`, `username`, `token_type`, `exp`, `iat`, `nbf`, `sub`, `aud`, `iss`, `jti`).
  - Extensibility: Custom request parameters and response extension claims are preserved and validated.
  - Helper properties: `scopes` parsed as `frozenset[str]` and UTC `datetime` objects for Unix timestamps (`exp_datetime`, `iat_datetime`, `nbf_datetime`).

## Installation

```bash
pip install lab-rfc7662-py
```

## Quickstart

### Parsing and Creating Token Introspection Requests

```python
from rfc7662 import IntrospectionRequest

# Parse an incoming application/x-www-form-urlencoded request body
req = IntrospectionRequest.from_urlencoded("token=mF_9.B5f-4.1JqM&token_type_hint=access_token")
assert req.token == "mF_9.B5f-4.1JqM"
assert req.token_type_hint == "access_token"

# Create a request programmatically and serialize to urlencoded
new_req = IntrospectionRequest(
    token="2YotnFZFEjr1zCsicMWpAA",
    token_type_hint="access_token",
    extra_parameters={"resource": "https://api.example.com"},
)
payload = new_req.to_urlencoded()
```

### Parsing and Creating Token Introspection Responses

```python
from rfc7662 import IntrospectionResponse

# Parse incoming JSON response
json_data = '''{
  "active": true,
  "scope": "read write email",
  "client_id": "l238j32",
  "username": "jdoe",
  "token_type": "Bearer",
  "exp": 1419356238,
  "sub": "Z5O3upPC88QrAjx00dis",
  "aud": "https://protected.example.net/resource"
}'''

response = IntrospectionResponse.from_json(json_data)
if response.active:
    print(f"Token is active for user: {response.username}")
    print(f"Scopes granted: {response.scopes}")
    print(f"Expires at (UTC): {response.exp_datetime}")

# Create an inactive response
inactive_resp = IntrospectionResponse(active=False)
json_str = inactive_resp.to_json()  # '{"active": false}'
```

## Public API Interface

```python
from typing import Any, Mapping, Optional, Sequence, Union
from datetime import datetime

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
    ) -> None: ...

    def to_urlencoded(self) -> str:
        """Serializes request to application/x-www-form-urlencoded format."""
        ...

    def to_dict(self) -> dict[str, str]:
        """Returns request fields as a dictionary of string parameters."""
        ...

    @classmethod
    def from_urlencoded(cls, body: Union[str, bytes]) -> "IntrospectionRequest":
        """Parses and validates an application/x-www-form-urlencoded request body."""
        ...

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "IntrospectionRequest":
        """Parses and validates a request dictionary."""
        ...

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
    ) -> None: ...

    @property
    def scopes(self) -> frozenset[str]:
        """Returns the scope member split into a frozenset of scope strings."""
        ...

    @property
    def exp_datetime(self) -> Optional[datetime]:
        """Returns exp as a UTC datetime if present."""
        ...

    @property
    def iat_datetime(self) -> Optional[datetime]:
        """Returns iat as a UTC datetime if present."""
        ...

    @property
    def nbf_datetime(self) -> Optional[datetime]:
        """Returns nbf as a UTC datetime if present."""
        ...

    def to_dict(self) -> dict[str, Any]:
        """Serializes response to a clean dictionary omitting None standard claims."""
        ...

    def to_json(self) -> str:
        """Serializes response to RFC-compliant JSON string."""
        ...

    @classmethod
    def from_json(cls, payload: Union[str, bytes]) -> "IntrospectionResponse":
        """Parses and validates an application/json string or bytes payload."""
        ...

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "IntrospectionResponse":
        """Parses and validates a dictionary into an IntrospectionResponse object."""
        ...
```

## Running Tests

Run the test suite using `pytest`:

```bash
pytest
```

## License

MIT

