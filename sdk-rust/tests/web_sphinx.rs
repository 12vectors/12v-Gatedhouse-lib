// Copyright (c) 2026 12vectors.com
// SPDX-License-Identifier: MIT
// See the LICENSE file in the repository root for the full license text.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::SystemTime;

use gatedhouse::{
    AuthenticatedSubject, EffectivePermission, FilterError, GatedContext, Gatedhouse,
    GatedhouseApiFilter, GatedhouseFactory, GatedhouseWebFilter, GroupManager, MembershipManager,
    PermissionCatalog, RoleManager, SphinxClient, TokenVerificationError, TokenVerificationReason,
    TokenVerifierConfig, WebFilterOutcome,
};
use serde_json::json;

fn subject() -> AuthenticatedSubject {
    let claims: HashMap<String, serde_json::Value> = [
        ("email".to_string(), json!("x@y.z")),
        ("role".to_string(), json!("admin")),
        ("scope".to_string(), json!("read write")),
        ("mfa_verified".to_string(), json!(true)),
        ("delegation_id".to_string(), json!("d1")),
        ("act".to_string(), json!({"sub": "agent"})),
    ]
    .into_iter()
    .collect();
    AuthenticatedSubject {
        id: "p1".to_string(),
        issuer: "i".to_string(),
        audience: "a".to_string(),
        issued_at: None,
        expires_at: SystemTime::now(),
        token_type: Some("access".to_string()),
        claims,
    }
}

struct StubGh {
    ok: bool,
}

impl Gatedhouse for StubGh {
    fn permission_catalog(&self) -> &dyn PermissionCatalog {
        unimplemented!()
    }
    fn role_manager(&self) -> &dyn RoleManager {
        unimplemented!()
    }
    fn membership_manager(&self) -> &dyn MembershipManager {
        unimplemented!()
    }
    fn group_manager(&self) -> &dyn GroupManager {
        unimplemented!()
    }
    fn has_permission(
        &self,
        _: &str,
        _: &str,
        _: &str,
        _: &str,
        _: &str,
    ) -> Result<bool, gatedhouse::GatedhouseError> {
        unimplemented!()
    }
    fn get_effective_permissions(
        &self,
        _: &str,
        _: &str,
    ) -> Result<Vec<EffectivePermission>, gatedhouse::GatedhouseError> {
        unimplemented!()
    }
    fn get_roles(&self, _: &str, _: &str) -> Result<Vec<String>, gatedhouse::GatedhouseError> {
        unimplemented!()
    }
    fn get_groups(&self, _: &str, _: &str) -> Result<Vec<String>, gatedhouse::GatedhouseError> {
        unimplemented!()
    }
    fn verify_token(&self, _: &str) -> Result<AuthenticatedSubject, TokenVerificationError> {
        if self.ok {
            Ok(subject())
        } else {
            Err(TokenVerificationError {
                reason: TokenVerificationReason::Expired,
                message: "expired".to_string(),
            })
        }
    }
    fn invalidate_cache(&self, _: &str, _: &str) {}
    fn invalidate_all_cache(&self) {}
    fn set_cache_bypass(&self, _: bool) {}
    fn is_cache_bypassed(&self) -> bool {
        false
    }
}

#[test]
fn gated_context_logic() {
    let ctx = GatedContext::from_subject(&subject());
    assert!(ctx.is_admin() && ctx.is_human() && ctx.is_delegated());
    assert!(ctx.has_scope("write") && !ctx.has_scope("writ"));
    assert_eq!(ctx.person_id, "p1");
    assert_eq!(ctx.actor_claims.as_ref().unwrap()["sub"], json!("agent"));
    assert_eq!(ctx.identity_type, "human");
}

#[test]
fn sphinx_url_builders() {
    let c = SphinxClient::new("https://sphinx.12v.sh/", "cid", "secret");
    assert_eq!(c.login_url("my app"), "https://sphinx.12v.sh/login?app=my+app");
    assert_eq!(
        c.federated_login_url("conn1", None),
        "https://sphinx.12v.sh/api/sphinx/v1/auth/federated/conn1"
    );
    assert!(c.federated_login_url("conn1", Some("app")).ends_with("/federated/conn1?app=app"));
}

#[test]
fn api_filter() {
    let f = GatedhouseApiFilter::new(Arc::new(StubGh { ok: true }));
    let ctx = f.authenticate(Some("Bearer tok")).unwrap();
    assert!(ctx.is_admin());
    let err = f.authenticate(None).unwrap_err();
    assert_eq!(err.status(), 401);
    assert!(err.to_json_body().contains("Missing or invalid Bearer token"));
    let f_bad = GatedhouseApiFilter::new(Arc::new(StubGh { ok: false }));
    let err = f_bad.authenticate(Some("Bearer bad")).unwrap_err();
    assert!(err.to_json_body().contains("Token verification failed"));

    assert!(GatedhouseApiFilter::require_admin(&ctx).is_ok());
    assert!(GatedhouseApiFilter::require_human(&ctx).is_ok());
    assert!(GatedhouseApiFilter::require_scope(&ctx, "read").is_ok());
    match GatedhouseApiFilter::require_scope(&ctx, "nope") {
        Err(FilterError::Forbidden(d)) => assert!(d.contains("'nope'")),
        other => panic!("expected Forbidden, got {other:?}"),
    }
}

#[test]
fn web_filter() {
    let w = GatedhouseWebFilter::new(Arc::new(StubGh { ok: true }));
    match w.check(None, "/myapp") {
        WebFilterOutcome::RedirectToLogin {
            location,
            clear_session_token,
        } => {
            assert_eq!(location, "/myapp/auth/login");
            assert!(!clear_session_token);
        }
        _ => panic!("expected redirect"),
    }
    match w.check(Some("tok"), "") {
        WebFilterOutcome::Authenticated(ctx) => assert!(ctx.is_admin()),
        _ => panic!("expected authenticated"),
    }
    let w_bad = GatedhouseWebFilter::with_config(
        Arc::new(StubGh { ok: false }),
        "https://sso.example/login",
        "access_token",
    );
    match w_bad.check(Some("bad"), "/ignored") {
        WebFilterOutcome::RedirectToLogin {
            location,
            clear_session_token,
        } => {
            assert_eq!(location, "https://sso.example/login");
            assert!(clear_session_token);
        }
        _ => panic!("expected redirect"),
    }
}

#[test]
fn just_token_verifier() {
    let gh = GatedhouseFactory::create_just_token_verifier(TokenVerifierConfig::new(
        "https://x/jwks",
        "i",
        "a",
    ));
    assert!(!gh.is_cache_bypassed());
    gh.invalidate_all_cache();
    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = gh.role_manager();
    }))
    .is_err();
    assert!(panicked);
}
