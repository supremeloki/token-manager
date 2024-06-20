import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import pytest

from token_manager import (
    ExpiredTokenError,
    HmacSigner,
    InvalidTokenError,
    OpaqueTokenStore,
    RevokedTokenError,
    TokenError,
)


@pytest.fixture
def store():
    return OpaqueTokenStore(ttl_seconds=60)


def test_issue_returns_usable_pair(store):
    pair = store.issue("sara", scopes=frozenset({"read"}))
    record = store.introspect(pair.access_token)
    assert record.subject == "sara"
    assert record.has_scope("read")
    assert not record.has_scope("admin")


def test_wildcard_scope_covers_all(store):
    pair = store.issue("root", scopes=frozenset({"*"}))
    assert store.introspect(pair.access_token).has_scope("anything")


def test_unknown_token_rejected(store):
    with pytest.raises(InvalidTokenError):
        store.introspect("garbage-token")


def test_empty_subject_rejected(store):
    with pytest.raises(InvalidTokenError):
        store.issue("")


def test_invalid_ttl_rejected():
    with pytest.raises(TokenError):
        OpaqueTokenStore(ttl_seconds=0)


def test_expiry_detected(store, monkeypatch):
    pair = store.issue("temp", ttl_seconds=1)
    real_time = time.time
    monkeypatch.setattr(time, "time", lambda: real_time() + 10)
    with pytest.raises(ExpiredTokenError):
        store.introspect(pair.access_token)


def test_revocation_kills_both_tokens(store):
    pair = store.issue("sara")
    store.revoke(pair.refresh_token)
    with pytest.raises(RevokedTokenError):
        store.introspect(pair.access_token)
    with pytest.raises(RevokedTokenError):
        store.introspect(pair.refresh_token)


def test_revoking_unknown_token_returns_false(store):
    assert store.revoke("nope") is False


def test_rotation_invalidate_old_and_issues_new(store):
    pair = store.issue("sara", scopes=frozenset({"write"}))
    fresh = store.rotate(pair.refresh_token)
    with pytest.raises((InvalidTokenError, RevokedTokenError)):
        store.introspect(pair.access_token)
    assert store.introspect(fresh.access_token).has_scope("write")


def test_purge_expired_removes_stale(store, monkeypatch):
    pair = store.issue("old", ttl_seconds=1)
    real_time = time.time
    monkeypatch.setattr(time, "time", lambda: real_time() + 5)
    removed = store.purge_expired()
    assert removed >= 1
    with pytest.raises(InvalidTokenError):
        store.introspect(pair.access_token)


def test_hmac_signer_roundtrip():
    signer = HmacSigner(b"k" * 16)
    token = signer.sign_payload({"sub": "sara", "role": "analyst"})
    payload = signer.verify_payload(token)
    assert payload["sub"] == "sara"


def test_tampered_signature_rejected():
    signer = HmacSigner(b"k" * 16)
    attacker = HmacSigner(b"evil" * 4)
    forged = attacker.sign_payload({"sub": "admin"})
    with pytest.raises(InvalidTokenError):
        signer.verify_payload(forged)


def test_malformed_token_rejected(signer=None):
    signer = HmacSigner(b"k" * 16)
    for bad in ["", "nodot", "a.b.c"]:
        with pytest.raises(InvalidTokenError):
            signer.verify_payload(bad)


def test_unsupported_algorithm_rejected():
    with pytest.raises(TokenError):
        HmacSigner(b"k" * 16, algorithm="md5")


def test_fingerprint_is_short_and_deterministic():
    signer = HmacSigner(b"k" * 16)
    token = signer.sign_payload({"n": 1})
    assert signer.fingerprint(token) == signer.fingerprint(token)
    assert len(signer.fingerprint(token)) == 16
