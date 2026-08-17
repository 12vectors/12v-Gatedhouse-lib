# Quickstart: verifying the WWW-Authenticate header

Any off-the-shelf HTTP client can verify the contract against an app embedding
a Gatedhouse API guard:

```bash
# Missing token → 401 with the challenge
curl -si http://localhost:8080/api/anything | grep -i '^WWW-Authenticate'
# → WWW-Authenticate: Bearer

# Invalid token → same challenge
curl -si -H 'Authorization: Bearer not-a-token' http://localhost:8080/api/anything \
  | grep -i '^WWW-Authenticate'
# → WWW-Authenticate: Bearer

# Authenticated-but-forbidden (403) → header absent
# Login-redirect pages (302) → header absent
```

Per-SDK test entry points:

- Java: `cd sdk-java && mvn test` (ApiFilter tests)
- Python: `cd sdk-python && python -m pytest tests/test_web.py tests/test_asgi.py`
- Rust: `cd sdk-rust && cargo test --test web_sphinx`
