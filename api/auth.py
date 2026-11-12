"""API-key authentication for trusted website-backend clients."""
import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from pathlib import Path

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

_BEARER = HTTPBearer(auto_error=False)
_TENANT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_MIN_SECRET_LENGTH = 32


@dataclass(frozen=True)
class ApiClient:
    tenant_id: str
    secret_digest: bytes


def load_api_clients(path):
    """Load provisioned tenant credentials without logging or returning their secrets."""
    try:
        with Path(path).open(encoding="utf-8") as source:
            entries = json.load(source)
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"Unable to read API credentials from {path}.") from error
    if not isinstance(entries, list) or not entries:
        raise ValueError("The API-key file must contain a non-empty JSON list.")

    clients = []
    key_ids = set()
    for index, entry in enumerate(entries, start=1):
        if not isinstance(entry, dict):
            raise ValueError(f"API-key entry {index} must be an object.")
        key_id, tenant_id, secret = entry.get("key_id"), entry.get("tenant_id"), entry.get("secret")
        if not isinstance(key_id, str) or not key_id.strip() or key_id in key_ids:
            raise ValueError(f"API-key entry {index} must have a unique, non-empty key_id.")
        if not isinstance(tenant_id, str) or not _TENANT_ID.fullmatch(tenant_id):
            raise ValueError(f"API-key entry {index} has an invalid tenant_id.")
        if not isinstance(secret, str) or len(secret) < _MIN_SECRET_LENGTH:
            raise ValueError(f"API-key entry {index} secret must be at least {_MIN_SECRET_LENGTH} characters.")
        key_ids.add(key_id)
        clients.append(ApiClient(tenant_id, hashlib.sha256(secret.encode("utf-8")).digest()))
    return tuple(clients)


def require_api_client(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_BEARER),
):
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Valid bearer credentials are required.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    supplied_digest = hashlib.sha256(credentials.credentials.encode("utf-8")).digest()
    matched_client = None
    for client in request.app.state.api_clients:
        if hmac.compare_digest(supplied_digest, client.secret_digest):
            matched_client = client
    if matched_client is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Valid bearer credentials are required.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return matched_client
