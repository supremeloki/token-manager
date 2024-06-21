# token-manager

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Token lifecycle management: opaque access/refresh pairs with revocation and rotation, plus an HMAC signer for stateless tokens — constant-time verified.

## 🚀 Overview

Two token strategies, one package. **OpaqueTokenStore** issues server-side access/refresh pairs: introspection hits an in-memory store, revocation kills both halves of a pair at once, and rotation invalidates the old pair atomically while carrying scopes forward. **HmacSigner** produces compact signed payloads (`base64url(json).hmac`) with `hmac.compare_digest` verification — no timing side-channels, no external JWT dependency.

## ✨ Features

- **Paired tokens:** access + refresh share one record; revoking either kills both
- **Rotation with replay protection:** old pair is invalidated the moment it's rotated
- **Scope model:** frozenset-based, `*` grants everything
- **Typed failures:** `InvalidTokenError` / `ExpiredTokenError` / `RevokedTokenError`
- **Expiry hygiene:** `purge_expired()` reclaims stale records; monkeypatch-friendly clock
- **HMAC signing:** sha256/sha384/sha512, URL-safe base64, sorted-key JSON payload
- **Tamper detection:** forged signatures and malformed tokens rejected with typed errors
- **Zero dependencies**

## 🚧 Structure

```
token-manager/
├── src/token_manager/
│   ├── __init__.py
│   └── core.py
├── tests/
│   └── test_core.py
├── README.md
└── pyproject.toml
```

## 📦 Installation

```bash
git clone https://github.com/supremeloki/token-manager.git
cd token-manager
python -m venv .venv
.venv\Scripts\activate
pip install -e ".[dev]"
```

## 📋 Requirements

- Python 3.11+
- No runtime dependencies

## 🏃 Quick Start

### Opaque pairs

```python
from token_manager import OpaqueTokenStore

store = OpaqueTokenStore(ttl_seconds=3600)
pair = store.issue("sara", scopes=frozenset({"reports:read"}), metadata={"dept": "finance"})

record = store.introspect(pair.access_token)
print(record.has_scope("reports:read"), pair.expires_in)

fresh = store.rotate(pair.refresh_token)
store.revoke(fresh.refresh_token)
```

### Stateless HMAC tokens

```python
from token_manager import HmacSigner

signer = HmacSigner(b"server-secret-key-16b")
token = signer.sign_payload({"sub": "sara", "exp": 1735689600})

payload = signer.verify_payload(token)
print(payload["sub"], signer.fingerprint(token))
```

## 🔧 Error Handling

```text
TokenError
├── InvalidTokenError     # unknown/malformed/forged
├── ExpiredTokenError     # past expires_at
└── RevokedTokenError     # explicitly revoked
```

## 🧪 Testing

```bash
pytest tests/ -v
```

## 📝 Code Quality

- Full type hints (`X | None` style), frozen TokenPair
- Zero comments — names carry the meaning
- Constant-time signature comparison via `hmac.compare_digest`

## 📄 License

MIT — see [LICENSE](LICENSE).

## 👤 Author

**Kooroush Masoumi**

---

⭐ Star this repo if you find it useful!
