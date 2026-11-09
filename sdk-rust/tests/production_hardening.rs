// Copyright (c) 2026 12vectors.com
// SPDX-License-Identifier: MIT
// See the LICENSE file in the repository root for the full license text.

//! Production behaviour, mirroring the Java and Python tests: auth
//! responses and the bounded cache. No database needed.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use gatedhouse::{
    bearer_token, AuthenticatedSubject, EffectivePermission, Gatedhouse, GatedhouseApiFilter,
    GatedhouseWebFilter, GroupManager, InMemoryPermissionCache, MembershipManager,
    PermissionCache, PermissionCatalog, PermissionExplanation, RoleManager,
    TokenVerificationError, TokenVerificationReason, WebFilterOutcome, RETRY_AFTER_SECONDS,
};

/// A Gatedhouse stand-in whose verify_token succeeds or fails with a reason.
struct Verifier(Option<TokenVerificationReason>);

impl Gatedhouse for Verifier {
    fn verify_token(&self, _: &str) -> Result<AuthenticatedSubject, TokenVerificationError> {
        match self.0 {
            Some(reason) => Err(TokenVerificationError {
                reason,
                message: "kid \"x\" from https://idp.internal".into(),
            }),
            None => Ok(AuthenticatedSubject {
                id: "u".into(),
                issuer: "i".into(),
                audience: "a".into(),
                issued_at: None,
                expires_at: std::time::SystemTime::now(),
                token_type: None,
                claims: HashMap::new(),
            }),
        }
    }
    fn permission_catalog(&self) -> &dyn PermissionCatalog { unimplemented!() }
    fn role_manager(&self) -> &dyn RoleManager { unimplemented!() }
    fn membership_manager(&self) -> &dyn MembershipManager { unimplemented!() }
    fn group_manager(&self) -> &dyn GroupManager { unimplemented!() }
    fn has_permission(&self, _: &str, _: &str, _: &str, _: &str, _: &str) -> Result<bool, gatedhouse::GatedhouseError> { unimplemented!() }
    fn get_effective_permissions(&self, _: &str, _: &str) -> Result<Vec<EffectivePermission>, gatedhouse::GatedhouseError> { unimplemented!() }
    fn explain_permission(&self, _: &str, _: &str, _: &str, _: &str, _: &str) -> Result<PermissionExplanation, gatedhouse::GatedhouseError> { unimplemented!() }
    fn get_roles(&self, _: &str, _: &str) -> Result<Vec<String>, gatedhouse::GatedhouseError> { unimplemented!() }
    fn get_groups(&self, _: &str, _: &str) -> Result<Vec<String>, gatedhouse::GatedhouseError> { unimplemented!() }
    fn invalidate_cache(&self, _: &str, _: &str) {}
    fn invalidate_all_cache(&self) {}
    fn set_cache_enabled(&self, _: bool) {}
    fn is_cache_enabled(&self) -> bool { false }
}

fn api(reason: Option<TokenVerificationReason>) -> GatedhouseApiFilter {
    GatedhouseApiFilter::new(Arc::new(Verifier(reason)))
}

#[test]
fn bodies_are_byte_identical_to_the_java_and_python_sdks() {
    let missing = api(None).authenticate(None).unwrap_err();
    assert_eq!(401, missing.status());
    assert_eq!(
        r#"{"error":"unauthorized","reason":"missing_token","detail":"Missing or invalid Bearer token"}"#,
        missing.to_json_body()
    );
    let invalid = api(Some(TokenVerificationReason::InvalidSignature))
        .authenticate(Some("Bearer t"))
        .unwrap_err();
    assert_eq!(
        r#"{"error":"unauthorized","reason":"invalid_signature","detail":"Token verification failed"}"#,
        invalid.to_json_body(),
        "a stable reason, never the verifier's internal message"
    );
    assert_eq!(Some(("WWW-Authenticate", "Bearer")), invalid.challenge_header());
}

#[test]
fn identity_provider_outage_is_503_not_401() {
    let err = api(Some(TokenVerificationReason::JwksUnavailable))
        .authenticate(Some("Bearer t"))
        .unwrap_err();
    assert_eq!(503, err.status());
    assert_eq!(Some(RETRY_AFTER_SECONDS), err.retry_after());
    assert_eq!(30, RETRY_AFTER_SECONDS);
    assert_eq!(None, err.challenge_header(), "the token is not at fault");
    assert_eq!(
        r#"{"error":"unavailable","reason":"jwks_unavailable","detail":"Token verification is temporarily unavailable"}"#,
        err.to_json_body()
    );
}

#[test]
fn bearer_scheme_is_case_insensitive() {
    for header in ["bearer t", "BEARER t", "Bearer   t  "] {
        assert!(api(None).authenticate(Some(header)).is_ok(), "{header}");
    }
    assert_eq!(Some("t"), bearer_token("bEaReR t"));
    assert_eq!(None, bearer_token("Bearer    "));
    assert_eq!(None, bearer_token("Basic dXNlcg=="));
    assert_eq!(None, bearer_token("Bear"));
}

#[test]
fn session_filter_keeps_the_session_through_an_outage() {
    let web = GatedhouseWebFilter::new(Arc::new(Verifier(Some(TokenVerificationReason::JwksUnavailable))));
    assert!(matches!(web.check(Some("tok"), ""), WebFilterOutcome::Unavailable));
    let web = GatedhouseWebFilter::new(Arc::new(Verifier(Some(TokenVerificationReason::Expired))));
    match web.check(Some("tok"), "/app") {
        WebFilterOutcome::RedirectToLogin { location, clear_session_token } => {
            assert_eq!("/app/auth/login", location);
            assert!(clear_session_token);
        }
        other => panic!("expected a redirect, got {other:?}"),
    }
}

#[test]
fn cache_never_grows_beyond_its_bound_and_keeps_the_newest() {
    let cache = InMemoryPermissionCache::with_ttl_and_max_entries(Duration::from_secs(60), 100);
    for i in 0..5000 {
        cache.put("user", &format!("org-{i}"), vec![]);
        assert!(cache.size() <= 100, "size {} after {i}", cache.size());
    }
    assert!(cache.get("user", "org-4999").is_some());
    assert!(cache.get("user", "org-0").is_none(), "oldest evicted first");
    assert!(cache.eviction_count() > 0);
    assert_eq!(10_000, InMemoryPermissionCache::new().max_entries());

    let one = InMemoryPermissionCache::with_ttl_and_max_entries(Duration::from_secs(60), 1);
    one.put("a", "o", vec![]);
    one.put("b", "o", vec![]);
    assert_eq!(1, one.size(), "a bound of one holds");
}

#[test]
#[should_panic(expected = "max_entries must be at least 1")]
fn cache_rejects_an_empty_bound() {
    let _ = InMemoryPermissionCache::with_ttl_and_max_entries(Duration::from_secs(1), 0);
}
