# Test fixtures

`jwks_test_key.pem` is a throwaway RSA key generated solely for the JWKS
unit tests in `src/jwt_verification.rs` (they sign tokens with it and serve
its public half from a local test server). It protects nothing and must
never be used anywhere else. The directory is excluded from the published
crate.
