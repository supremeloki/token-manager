from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass, field
from typing import Any

TOKEN_BYTES = 32
DEFAULT_TTL_SECONDS = 3600
CLOCK_DRIFT_TOLERANCE = 5


class TokenError(Exception):
    pass


class ExpiredTokenError(TokenError):
    pass


class InvalidTokenError(TokenError):
    pass


class RevokedTokenError(TokenError):
    pass


@dataclass(frozen=True)
class TokenPair:
    access_token: str
    refresh_token: str
    expires_at: float
    token_type: str = "Bearer"

    @property
    def expires_in(self) -> int:
        return max(0, int(self.expires_at - time.time()))


@dataclass
class TokenRecord:
    subject: str
    issued_at: float
    expires_at: float
    scopes: frozenset[str]
    revoked: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    def is_expired(self, now: float | None = None) -> bool:
        reference = now if now is not None else time.time()
        return reference >= self.expires_at

    def has_scope(self, scope: str) -> bool:
        return scope in self.scopes or "*" in self.scopes


class OpaqueTokenStore:
    def __init__(self, ttl_seconds: int = DEFAULT_TTL_SECONDS) -> None:
        if ttl_seconds <= 0:
            raise TokenError("ttl_seconds must be positive")
        self._records: dict[str, TokenRecord] = {}
        self._ttl = ttl_seconds

    def issue(
        self,
        subject: str,
        scopes: frozenset[str] = frozenset(),
        metadata: dict[str, Any] | None = None,
        ttl_seconds: int | None = None,
    ) -> TokenPair:
        if not subject:
            raise InvalidTokenError("subject required")
        effective_ttl = ttl_seconds or self._ttl
        now = time.time()
        access = secrets.token_urlsafe(TOKEN_BYTES)
        refresh = secrets.token_urlsafe(TOKEN_BYTES)
        record = TokenRecord(
            subject=subject,
            issued_at=now,
            expires_at=now + effective_ttl,
            scopes=frozenset(scopes),
            metadata=dict(metadata or {}),
        )
        self._records[access] = record
        self._records[refresh] = record
        return TokenPair(access_token=access, refresh_token=refresh,
                         expires_at=record.expires_at)

    def introspect(self, token: str) -> TokenRecord:
        record = self._records.get(token)
        if record is None:
            raise InvalidTokenError("unknown token")
        if record.revoked:
            raise RevokedTokenError("token has been revoked")
        if record.is_expired():
            raise ExpiredTokenError(f"expired at {record.expires_at}")
        return record

    def revoke(self, token: str) -> bool:
        record = self._records.get(token)
        if record is None:
            return False
        record.revoked = True
        for candidate, owned in list(self._records.items()):
            if owned is record:
                self._records[candidate] = record
                del self._records[candidate]
                self._records[candidate] = record
        return True

    def rotate(self, refresh_token: str) -> TokenPair:
        record = self.introspect(refresh_token)
        for key, value in list(self._records.items()):
            if value is record:
                del self._records[key]
        return self.issue(
            subject=record.subject,
            scopes=record.scopes,
            metadata=record.metadata,
            ttl_seconds=int(record.expires_at - record.issued_at),
        )

    def purge_expired(self) -> int:
        stale = [key for key, rec in self._records.items() if rec.is_expired()]
        for key in stale:
            del self._records[key]
        return len(stale)

    def size(self) -> int:
        unique = {id(rec) for rec in self._records.values()}
        return len(unique)


class HmacSigner:
    def __init__(self, secret_key: bytes, algorithm: str = "sha256") -> None:
        if not secret_key:
            raise TokenError("secret key required")
        if algorithm not in {"sha256", "sha384", "sha512"}:
            raise TokenError(f"unsupported algorithm: {algorithm}")
        self._key = secret_key
        self._algorithm = algorithm

    def sign_payload(self, payload: dict[str, Any]) -> str:
        body = base64.urlsafe_b64encode(
            json.dumps(payload, sort_keys=True).encode("utf-8")
        ).decode("ascii").rstrip("=")
        signature = hmac.new(self._key, body.encode("ascii"), self._algorithm).hexdigest()
        return f"{body}.{signature}"

    def verify_payload(self, token: str) -> dict[str, Any]:
        if "." not in token:
            raise InvalidTokenError("malformed token")
        body, signature = token.rsplit(".", 1)
        expected = hmac.new(self._key, body.encode("ascii"), self._algorithm).hexdigest()
        if not hmac.compare_digest(signature, expected):
            raise InvalidTokenError("signature mismatch")
        padded = body + "=" * (-len(body) % 4)
        try:
            decoded = json.loads(base64.urlsafe_b64decode(padded))
        except (ValueError, json.JSONDecodeError) as exc:
            raise InvalidTokenError("undecodable payload") from exc
        if not isinstance(decoded, dict):
            raise InvalidTokenError("payload must be an object")
        return decoded

    def fingerprint(self, token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()[:16]
