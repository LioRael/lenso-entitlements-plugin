//! Plugin-owned entitlement grant facts with monotonic policy revisions.

mod operator;
mod schema;

use std::{cell::RefCell, fmt, fmt::Write as _, rc::Rc, time::Duration};

use lenso::{ActivateContext, DeactivateContext, Lifecycle, Port, provides};
use lenso_capability_entitlements as entitlements;
use lenso_capability_entitlements::{
    Entitlements, ResolveEntitlementError, ResolveEntitlementRequest, ResolveEntitlementResponse,
};
use lenso_capability_entitlements_admin as admin;
use lenso_capability_entitlements_admin::{
    EntitlementsAdminPutGrant, EntitlementsAdminRevokeGrant, PutGrantError, PutGrantRequest,
    PutGrantResponse, RevokeGrantError, RevokeGrantRequest, RevokeGrantResponse,
};
use lenso_capability_secrets as secrets;
use lenso_capability_secrets::{ResolveRequest, SecretsClient, SecretsInvocationError};
use lenso_kernel::{InvocationContext, NativeRequestFuture, RuntimeFailure};
use lenso_postgres_kit::OwnedPostgres;
use serde::{Deserialize, Serialize};
use sqlx::Row;
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use zeroize::Zeroizing;

use crate::schema::schema_plan;

pub use operator::{EntitlementsOperator, EntitlementsOperatorError};

const DEPENDENCY_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EntitlementsConfig {
    schema: String,
    database_url_secret: String,
    resolve_callers: Vec<String>,
    admin_callers: Vec<String>,
}

impl EntitlementsConfig {
    pub fn new(
        schema: impl Into<String>,
        database_url_secret: impl Into<String>,
        resolve_callers: Vec<String>,
        admin_callers: Vec<String>,
    ) -> Result<Self, EntitlementsConfigError> {
        let value = Self {
            schema: schema.into(),
            database_url_secret: database_url_secret.into(),
            resolve_callers,
            admin_callers,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), EntitlementsConfigError> {
        schema_plan(self.schema.clone()).map_err(|_| EntitlementsConfigError::InvalidSchema)?;
        if !valid_secret_reference(&self.database_url_secret) {
            return Err(EntitlementsConfigError::InvalidSecretReference);
        }
        if self.resolve_callers.is_empty()
            || self
                .resolve_callers
                .iter()
                .any(|caller| !valid_name(caller))
        {
            return Err(EntitlementsConfigError::InvalidResolveCallers);
        }
        if self.admin_callers.is_empty()
            || self.admin_callers.iter().any(|caller| !valid_name(caller))
        {
            return Err(EntitlementsConfigError::InvalidAdminCallers);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum EntitlementsConfigError {
    #[error("invalid owned PostgreSQL schema")]
    InvalidSchema,
    #[error("invalid database URL secret reference")]
    InvalidSecretReference,
    #[error("at least one valid Entitlements caller is required")]
    InvalidResolveCallers,
    #[error("at least one valid Entitlements Admin caller is required")]
    InvalidAdminCallers,
}

fn validate_config(config: &EntitlementsConfig) -> Result<(), RuntimeFailure> {
    config
        .validate()
        .map_err(|error| RuntimeFailure::InvalidResolvedPlan {
            detail: error.to_string(),
        })
}

#[lenso::plugin(
    lifecycle,
    configuration_schema = "configuration.schema.json",
    validate = validate_config
)]
#[derive(Clone)]
struct EntitlementsPlugin {
    #[config]
    config: EntitlementsConfig,
    secrets: Port<secrets::SecretsClient>,
    state: Rc<RefCell<Option<PreparedEntitlements>>>,
}

#[derive(Clone)]
struct PreparedEntitlements {
    postgres: OwnedPostgres,
}

impl fmt::Debug for PreparedEntitlements {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedEntitlements")
            .field("schema", &self.postgres.schema())
            .finish()
    }
}

impl fmt::Debug for EntitlementsPlugin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EntitlementsPlugin")
            .field("prepared", &self.state.borrow().is_some())
            .field("resolve_caller_count", &self.config.resolve_callers.len())
            .field("admin_caller_count", &self.config.admin_callers.len())
            .finish_non_exhaustive()
    }
}

#[provides(entitlements::Entitlements, admin::EntitlementsAdmin)]
impl EntitlementsPlugin {}

impl EntitlementsPlugin {
    fn prepared(&self) -> Result<PreparedEntitlements, RuntimeFailure> {
        self.state
            .borrow()
            .clone()
            .ok_or(RuntimeFailure::PluginFailure {
                detail: "Entitlements Plugin is not prepared".to_owned(),
            })
    }

    fn admin_authorized(&self, context: &InvocationContext) -> bool {
        context.caller_instance().is_some_and(|caller| {
            self.config
                .admin_callers
                .iter()
                .any(|allowed| allowed == caller)
        })
    }

    fn resolve_authorized(&self, context: &InvocationContext) -> bool {
        context.caller_instance().is_some_and(|caller| {
            self.config
                .resolve_callers
                .iter()
                .any(|allowed| allowed == caller)
        })
    }

    #[allow(clippy::needless_pass_by_value)]
    fn resolve_entitlement(
        &self,
        context: InvocationContext,
        request: ResolveEntitlementRequest,
    ) -> NativeRequestFuture<Entitlements> {
        let authorized = self.resolve_authorized(&context);
        let valid = valid_dimension(&request.scope_kind)
            && valid_name(&request.scope_id)
            && valid_name(&request.subject)
            && valid_dimension(&request.feature);
        let prepared = self.prepared();
        Box::pin(async move {
            if !authorized {
                return Ok(Err(ResolveEntitlementError::Forbidden));
            }
            if !valid {
                return Ok(Err(ResolveEntitlementError::InvalidRequest));
            }
            let prepared = prepared?;
            let row = sqlx::query(
                "SELECT s.policy_revision,g.grant_id,g.limit_value FROM entitlement_scopes s LEFT JOIN entitlement_grants g ON g.scope_kind=s.scope_kind AND g.scope_id=s.scope_id AND g.subject=$3 AND g.feature_key=$4 AND g.revoked_at IS NULL AND (g.expires_at IS NULL OR g.expires_at>transaction_timestamp()) WHERE s.scope_kind=$1 AND s.scope_id=$2",
            )
            .bind(&request.scope_kind)
            .bind(&request.scope_id)
            .bind(&request.subject)
            .bind(&request.feature)
            .fetch_optional(prepared.postgres.pool())
            .await
            .map_err(|source| runtime(EntitlementsError::Database {
                operation: "resolve entitlement",
                source,
            }))?;
            let Some(row) = row else {
                return Ok(Ok(ResolveEntitlementResponse {
                    granted: false,
                    grant_id: None,
                    limit: None,
                    policy_revision: 0,
                }));
            };
            let grant_id: Option<String> = row.try_get("grant_id").map_err(|source| {
                runtime(EntitlementsError::Database {
                    operation: "decode entitlement grant",
                    source,
                })
            })?;
            let limit: Option<i64> = row.try_get("limit_value").map_err(|source| {
                runtime(EntitlementsError::Database {
                    operation: "decode entitlement limit",
                    source,
                })
            })?;
            let policy_revision = row.try_get("policy_revision").map_err(|source| {
                runtime(EntitlementsError::Database {
                    operation: "decode entitlement revision",
                    source,
                })
            })?;
            Ok(Ok(ResolveEntitlementResponse {
                granted: grant_id.is_some(),
                grant_id,
                limit: limit.map(|value| value.to_string()),
                policy_revision,
            }))
        })
    }

    #[allow(clippy::needless_pass_by_value, clippy::too_many_lines)]
    fn put_grant(
        &self,
        context: InvocationContext,
        request: PutGrantRequest,
    ) -> NativeRequestFuture<EntitlementsAdminPutGrant> {
        let authorized = self.admin_authorized(&context);
        let prepared = self.prepared();
        Box::pin(async move {
            if !authorized {
                return Ok(Err(PutGrantError::Forbidden));
            }
            if !valid_dimension(&request.scope_kind)
                || !valid_name(&request.scope_id)
                || !valid_name(&request.subject)
                || !valid_dimension(&request.feature)
            {
                return Ok(Err(PutGrantError::InvalidGrant));
            }
            let limit = request
                .limit
                .as_deref()
                .map(str::parse::<i64>)
                .transpose()
                .ok()
                .filter(|value| value.is_none_or(|value| value > 0));
            let Some(limit) = limit else {
                return Ok(Err(PutGrantError::InvalidGrant));
            };
            let expires_at = request
                .expires_at
                .as_deref()
                .map(|value| OffsetDateTime::parse(value, &Rfc3339))
                .transpose()
                .ok()
                .filter(|value| value.as_ref().is_none_or(pg_timestamp_representable));
            let Some(expires_at) = expires_at else {
                return Ok(Err(PutGrantError::InvalidGrant));
            };
            if expires_at.is_some_and(|value| value <= OffsetDateTime::now_utc()) {
                return Ok(Err(PutGrantError::InvalidGrant));
            }
            let prepared = prepared?;
            let mut transaction = prepared.postgres.pool().begin().await.map_err(|source| {
                runtime(EntitlementsError::Database {
                    operation: "begin entitlement grant",
                    source,
                })
            })?;
            sqlx::query("INSERT INTO entitlement_scopes(scope_kind,scope_id) VALUES($1,$2) ON CONFLICT DO NOTHING")
                .bind(&request.scope_kind)
                .bind(&request.scope_id)
                .execute(&mut *transaction)
                .await
                .map_err(|source| runtime(EntitlementsError::Database { operation: "ensure entitlement scope", source }))?;
            let revision: i64 = sqlx::query_scalar("SELECT policy_revision FROM entitlement_scopes WHERE scope_kind=$1 AND scope_id=$2 FOR UPDATE")
                .bind(&request.scope_kind)
                .bind(&request.scope_id)
                .fetch_one(&mut *transaction)
                .await
                .map_err(|source| runtime(EntitlementsError::Database { operation: "lock entitlement scope", source }))?;
            let existing = sqlx::query("SELECT grant_id,limit_value,expires_at,revoked_at FROM entitlement_grants WHERE scope_kind=$1 AND scope_id=$2 AND subject=$3 AND feature_key=$4 FOR UPDATE")
                .bind(&request.scope_kind)
                .bind(&request.scope_id)
                .bind(&request.subject)
                .bind(&request.feature)
                .fetch_optional(&mut *transaction)
                .await
                .map_err(|source| runtime(EntitlementsError::Database { operation: "lock entitlement grant", source }))?;
            let (grant_id, changed) = if let Some(row) = existing {
                let grant_id: String = row.try_get("grant_id").map_err(|source| {
                    runtime(EntitlementsError::Database {
                        operation: "decode entitlement grant id",
                        source,
                    })
                })?;
                let current_limit: Option<i64> = row.try_get("limit_value").map_err(|source| {
                    runtime(EntitlementsError::Database {
                        operation: "decode current entitlement limit",
                        source,
                    })
                })?;
                let current_expiry: Option<OffsetDateTime> =
                    row.try_get("expires_at").map_err(|source| {
                        runtime(EntitlementsError::Database {
                            operation: "decode current entitlement expiry",
                            source,
                        })
                    })?;
                let revoked_at: Option<OffsetDateTime> =
                    row.try_get("revoked_at").map_err(|source| {
                        runtime(EntitlementsError::Database {
                            operation: "decode entitlement revocation",
                            source,
                        })
                    })?;
                let changed =
                    current_limit != limit || current_expiry != expires_at || revoked_at.is_some();
                if changed {
                    sqlx::query("UPDATE entitlement_grants SET limit_value=$2,expires_at=$3,revoked_at=NULL,updated_at=transaction_timestamp() WHERE grant_id=$1")
                        .bind(&grant_id)
                        .bind(limit)
                        .bind(expires_at)
                        .execute(&mut *transaction)
                        .await
                        .map_err(|source| runtime(EntitlementsError::Database { operation: "update entitlement grant", source }))?;
                }
                (grant_id, changed)
            } else {
                let grant_id = random_id("grant_").map_err(runtime)?;
                sqlx::query("INSERT INTO entitlement_grants(grant_id,scope_kind,scope_id,subject,feature_key,limit_value,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7)")
                    .bind(&grant_id)
                    .bind(&request.scope_kind)
                    .bind(&request.scope_id)
                    .bind(&request.subject)
                    .bind(&request.feature)
                    .bind(limit)
                    .bind(expires_at)
                    .execute(&mut *transaction)
                    .await
                    .map_err(|source| runtime(EntitlementsError::Database { operation: "insert entitlement grant", source }))?;
                (grant_id, true)
            };
            let policy_revision = if changed {
                sqlx::query_scalar("UPDATE entitlement_scopes SET policy_revision=policy_revision+1 WHERE scope_kind=$1 AND scope_id=$2 RETURNING policy_revision")
                    .bind(&request.scope_kind)
                    .bind(&request.scope_id)
                    .fetch_one(&mut *transaction)
                    .await
                    .map_err(|source| runtime(EntitlementsError::Database { operation: "advance entitlement revision", source }))?
            } else {
                revision
            };
            transaction.commit().await.map_err(|source| {
                runtime(EntitlementsError::Database {
                    operation: "commit entitlement grant",
                    source,
                })
            })?;
            Ok(Ok(PutGrantResponse {
                grant_id,
                changed,
                policy_revision,
            }))
        })
    }

    #[allow(clippy::needless_pass_by_value)]
    fn revoke_grant(
        &self,
        context: InvocationContext,
        request: RevokeGrantRequest,
    ) -> NativeRequestFuture<EntitlementsAdminRevokeGrant> {
        let authorized = self.admin_authorized(&context);
        let prepared = self.prepared();
        Box::pin(async move {
            if !authorized {
                return Ok(Err(RevokeGrantError::Forbidden));
            }
            if !valid_name(&request.grant_id) {
                return Ok(Err(RevokeGrantError::InvalidGrant));
            }
            let prepared = prepared?;
            let mut transaction = prepared.postgres.pool().begin().await.map_err(|source| {
                runtime(EntitlementsError::Database {
                    operation: "begin entitlement revocation",
                    source,
                })
            })?;
            let location =
                sqlx::query("SELECT scope_kind,scope_id FROM entitlement_grants WHERE grant_id=$1")
                    .bind(&request.grant_id)
                    .fetch_optional(&mut *transaction)
                    .await
                    .map_err(|source| {
                        runtime(EntitlementsError::Database {
                            operation: "locate entitlement grant",
                            source,
                        })
                    })?;
            let Some(location) = location else {
                return Ok(Err(RevokeGrantError::NotFound));
            };
            let scope_kind: String = location.try_get("scope_kind").map_err(|source| {
                runtime(EntitlementsError::Database {
                    operation: "decode entitlement scope kind",
                    source,
                })
            })?;
            let scope_id: String = location.try_get("scope_id").map_err(|source| {
                runtime(EntitlementsError::Database {
                    operation: "decode entitlement scope id",
                    source,
                })
            })?;
            let revision: i64 = sqlx::query_scalar("SELECT policy_revision FROM entitlement_scopes WHERE scope_kind=$1 AND scope_id=$2 FOR UPDATE")
                .bind(&scope_kind)
                .bind(&scope_id)
                .fetch_one(&mut *transaction)
                .await
                .map_err(|source| runtime(EntitlementsError::Database { operation: "lock entitlement scope", source }))?;
            let changed = sqlx::query("UPDATE entitlement_grants SET revoked_at=transaction_timestamp(),updated_at=transaction_timestamp() WHERE grant_id=$1 AND revoked_at IS NULL")
                .bind(&request.grant_id)
                .execute(&mut *transaction)
                .await
                .map_err(|source| runtime(EntitlementsError::Database { operation: "revoke entitlement grant", source }))?
                .rows_affected() == 1;
            let policy_revision = if changed {
                sqlx::query_scalar("UPDATE entitlement_scopes SET policy_revision=policy_revision+1 WHERE scope_kind=$1 AND scope_id=$2 RETURNING policy_revision")
                    .bind(&scope_kind)
                    .bind(&scope_id)
                    .fetch_one(&mut *transaction)
                    .await
                    .map_err(|source| runtime(EntitlementsError::Database { operation: "advance entitlement revision", source }))?
            } else {
                revision
            };
            transaction.commit().await.map_err(|source| {
                runtime(EntitlementsError::Database {
                    operation: "commit entitlement revocation",
                    source,
                })
            })?;
            Ok(Ok(RevokeGrantResponse {
                changed,
                policy_revision,
            }))
        })
    }
}

impl Lifecycle for EntitlementsPlugin {
    async fn activate(&self, context: ActivateContext) -> Result<(), RuntimeFailure> {
        let dependencies = context.dependencies().clone();
        let cancellation = context.cancellation();
        let database_url = resolve_secret(
            &self.secrets,
            &dependencies,
            cancellation,
            &self.config.database_url_secret,
        )
        .await?;
        let postgres = OwnedPostgres::prepare(
            &database_url,
            schema_plan(self.config.schema.clone()).map_err(|error| {
                RuntimeFailure::InvalidResolvedPlan {
                    detail: error.to_string(),
                }
            })?,
        )
        .await
        .map_err(|error| RuntimeFailure::PluginFailure {
            detail: error.to_string(),
        })?;
        self.state.replace(Some(PreparedEntitlements { postgres }));
        Ok(())
    }

    async fn deactivate(&self, _context: DeactivateContext) -> Result<(), RuntimeFailure> {
        let prepared = self.state.borrow_mut().take();
        if let Some(prepared) = prepared {
            prepared.postgres.pool().close().await;
        }
        Ok(())
    }
}

#[derive(Debug, Error)]
enum EntitlementsError {
    #[error("PostgreSQL operation `{operation}` failed")]
    Database {
        operation: &'static str,
        #[source]
        source: sqlx::Error,
    },
    #[error("random source unavailable")]
    Random,
}

fn runtime(error: impl fmt::Display) -> RuntimeFailure {
    RuntimeFailure::PluginFailure {
        detail: error.to_string(),
    }
}

fn random_id(prefix: &str) -> Result<String, EntitlementsError> {
    let mut bytes = [0_u8; 18];
    getrandom::fill(&mut bytes).map_err(|_| EntitlementsError::Random)?;
    let mut id = String::with_capacity(prefix.len() + bytes.len() * 2);
    id.push_str(prefix);
    for byte in bytes {
        write!(&mut id, "{byte:02x}").expect("writing to String cannot fail");
    }
    Ok(id)
}

fn valid_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
}

fn valid_dimension(value: &str) -> bool {
    valid_name(value) && !value.starts_with('.') && !value.ends_with('.')
}

fn pg_timestamp_representable(value: &OffsetDateTime) -> bool {
    value.nanosecond().is_multiple_of(1_000)
}

fn valid_secret_reference(reference: &str) -> bool {
    !reference.is_empty()
        && reference.len() <= 256
        && !reference.starts_with('/')
        && !reference.ends_with('/')
        && !reference.contains("//")
        && reference
            .split('/')
            .all(|segment| segment != "." && segment != "..")
        && reference
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'/'))
}

async fn resolve_secret(
    secrets: &SecretsClient,
    dependencies: &lenso_kernel::PluginDependencies,
    cancellation: lenso_kernel::CancellationToken,
    reference: &str,
) -> Result<Zeroizing<String>, RuntimeFailure> {
    let context = dependencies.invocation_context_after(DEPENDENCY_TIMEOUT, cancellation)?;
    secrets
        .resolve_with_context(
            context,
            ResolveRequest {
                reference: reference.to_owned(),
            },
        )
        .await
        .map(|value| Zeroizing::new(value.value))
        .map_err(|error| match error {
            SecretsInvocationError::Domain(_) => RuntimeFailure::PluginFailure {
                detail: format!("secret `{reference}` was rejected"),
            },
            SecretsInvocationError::Runtime(error) => error,
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use lenso_kernel::CancellationToken;
    use sqlx::{AssertSqlSafe, Executor};

    fn plugin() -> EntitlementsPlugin {
        EntitlementsPlugin {
            config: EntitlementsConfig::new(
                "entitlements",
                "entitlements/database",
                vec!["billing-service".to_owned()],
                vec!["billing-admin".to_owned()],
            )
            .unwrap(),
            secrets: Port::default(),
            state: Rc::new(RefCell::new(None)),
        }
    }

    #[test]
    fn configuration_rejects_ambient_admin_authority() {
        assert_eq!(
            EntitlementsConfig::new(
                "entitlements",
                "entitlements/database",
                vec!["billing-service".to_owned()],
                Vec::new(),
            )
            .unwrap_err(),
            EntitlementsConfigError::InvalidAdminCallers
        );
    }

    #[test]
    fn configuration_rejects_ambient_resolve_authority() {
        assert_eq!(
            EntitlementsConfig::new(
                "entitlements",
                "entitlements/database",
                Vec::new(),
                vec!["billing-admin".to_owned()],
            )
            .unwrap_err(),
            EntitlementsConfigError::InvalidResolveCallers
        );
    }

    #[tokio::test]
    async fn forbidden_admin_fails_before_storage_access() {
        let context = InvocationContext::new(1, None, CancellationToken::new())
            .with_caller_instance("untrusted");
        let result = plugin()
            .put_grant(
                context,
                PutGrantRequest {
                    scope_kind: "organization".to_owned(),
                    scope_id: "org_acme".to_owned(),
                    subject: "org_acme".to_owned(),
                    feature: "reports.export".to_owned(),
                    limit: Some("10".to_owned()),
                    expires_at: None,
                },
            )
            .await
            .unwrap();
        assert_eq!(result, Err(PutGrantError::Forbidden));
    }

    #[tokio::test]
    async fn malformed_query_is_a_domain_error_before_storage_access() {
        let result = plugin()
            .resolve_entitlement(
                InvocationContext::new(1, None, CancellationToken::new())
                    .with_caller_instance("billing-service"),
                ResolveEntitlementRequest {
                    scope_kind: "organization".to_owned(),
                    scope_id: String::new(),
                    subject: "org_acme".to_owned(),
                    feature: "reports.export".to_owned(),
                },
            )
            .await
            .unwrap();
        assert_eq!(result, Err(ResolveEntitlementError::InvalidRequest));
    }

    #[tokio::test]
    async fn untrusted_resolver_is_rejected_before_storage_access() {
        let result = plugin()
            .resolve_entitlement(
                InvocationContext::new(1, None, CancellationToken::new())
                    .with_caller_instance("untrusted"),
                ResolveEntitlementRequest {
                    scope_kind: "organization".to_owned(),
                    scope_id: "org_acme".to_owned(),
                    subject: "org_acme".to_owned(),
                    feature: "reports.export".to_owned(),
                },
            )
            .await
            .unwrap();
        assert_eq!(result, Err(ResolveEntitlementError::Forbidden));
    }

    #[tokio::test]
    async fn sub_microsecond_expiry_is_rejected_before_storage_access() {
        let context = InvocationContext::new(1, None, CancellationToken::new())
            .with_caller_instance("billing-admin");
        let result = plugin()
            .put_grant(
                context,
                PutGrantRequest {
                    scope_kind: "organization".to_owned(),
                    scope_id: "org_acme".to_owned(),
                    subject: "org_acme".to_owned(),
                    feature: "reports.export".to_owned(),
                    limit: None,
                    expires_at: Some("2099-01-01T00:00:00.000000001Z".to_owned()),
                },
            )
            .await
            .unwrap();
        assert_eq!(result, Err(PutGrantError::InvalidGrant));
    }

    #[tokio::test]
    #[ignore = "requires LENSO_POSTGRES_TEST_URL"]
    async fn grant_revision_and_default_deny_are_transactional() {
        let database_url =
            std::env::var("LENSO_POSTGRES_TEST_URL").expect("LENSO_POSTGRES_TEST_URL is required");
        let schema = random_id("entitlements_test_").unwrap();
        EntitlementsOperator::setup(&database_url, &schema)
            .await
            .unwrap();
        let postgres = OwnedPostgres::prepare(&database_url, schema_plan(schema.clone()).unwrap())
            .await
            .unwrap();
        let plugin = plugin();
        plugin
            .state
            .replace(Some(PreparedEntitlements { postgres }));
        let admin_context = InvocationContext::new(1, None, CancellationToken::new())
            .with_caller_instance("billing-admin");
        let request = PutGrantRequest {
            scope_kind: "organization".to_owned(),
            scope_id: "org_acme".to_owned(),
            subject: "org_acme".to_owned(),
            feature: "reports.export".to_owned(),
            limit: Some("10".to_owned()),
            expires_at: None,
        };
        let first = plugin
            .put_grant(admin_context.clone(), request.clone())
            .await
            .unwrap()
            .unwrap();
        assert!(first.changed);
        assert_eq!(first.policy_revision, 1);
        let repeated = plugin
            .put_grant(admin_context.clone(), request)
            .await
            .unwrap()
            .unwrap();
        assert!(!repeated.changed);
        assert_eq!(repeated.policy_revision, 1);
        let resolved = plugin
            .resolve_entitlement(
                InvocationContext::new(2, None, CancellationToken::new())
                    .with_caller_instance("billing-service"),
                ResolveEntitlementRequest {
                    scope_kind: "organization".to_owned(),
                    scope_id: "org_acme".to_owned(),
                    subject: "org_acme".to_owned(),
                    feature: "reports.export".to_owned(),
                },
            )
            .await
            .unwrap()
            .unwrap();
        assert!(resolved.granted);
        assert_eq!(resolved.limit.as_deref(), Some("10"));
        let revoked = plugin
            .revoke_grant(
                admin_context,
                RevokeGrantRequest {
                    grant_id: first.grant_id,
                },
            )
            .await
            .unwrap()
            .unwrap();
        assert!(revoked.changed);
        assert_eq!(revoked.policy_revision, 2);
        let denied = plugin
            .resolve_entitlement(
                InvocationContext::new(3, None, CancellationToken::new())
                    .with_caller_instance("billing-service"),
                ResolveEntitlementRequest {
                    scope_kind: "organization".to_owned(),
                    scope_id: "org_acme".to_owned(),
                    subject: "org_acme".to_owned(),
                    feature: "reports.export".to_owned(),
                },
            )
            .await
            .unwrap()
            .unwrap();
        assert!(!denied.granted);
        assert_eq!(denied.policy_revision, 2);

        let cleanup_pool = sqlx::PgPool::connect(&database_url).await.unwrap();
        cleanup_pool
            .execute(AssertSqlSafe(format!("DROP SCHEMA \"{schema}\" CASCADE")))
            .await
            .unwrap();
        cleanup_pool.close().await;
    }
}
