//! Authoritative source for the Entitlements Admin Capability contract.

use lenso_contract_authoring as lenso;

#[derive(serde::Deserialize)]
pub struct Nullable<T>(Option<T>);

impl<T: lenso::JsonSchema> lenso::JsonSchema for Nullable<T> {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        format!("Nullable_{}", T::schema_name()).into()
    }

    fn schema_id() -> std::borrow::Cow<'static, str> {
        format!("Nullable<{}>", T::schema_id()).into()
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        <Option<T> as lenso::JsonSchema>::json_schema(generator)
    }
}

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct PutGrantRequest {
    pub scope_kind: String,
    pub scope_id: String,
    pub subject: String,
    pub feature: String,
    /// Positive base-10 int64 encoded as a portable string.
    pub limit: Nullable<String>,
    /// RFC 3339 timestamp that resolves to a whole microsecond.
    #[schemars(extend("format" = "date-time"))]
    pub expires_at: Nullable<String>,
}

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct PutGrantResponse {
    pub grant_id: String,
    pub changed: bool,
    #[schemars(range(min = 0))]
    pub policy_revision: i64,
}

#[derive(lenso::DomainError)]
pub enum PutGrantError {
    InvalidGrant,
    Forbidden,
}

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct RevokeGrantRequest {
    pub grant_id: String,
}

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct RevokeGrantResponse {
    pub changed: bool,
    #[schemars(range(min = 0))]
    pub policy_revision: i64,
}

#[derive(lenso::DomainError)]
pub enum RevokeGrantError {
    InvalidGrant,
    NotFound,
    Forbidden,
}

#[lenso::capability(
    id = "lenso.entitlements-admin",
    major = 1,
    version = "1.0.0",
    portable = true,
    cross_lane_transfer = true
)]
pub trait EntitlementsAdmin {
    async fn put_grant(
        &self,
        context: lenso::Ctx<'_>,
        request: PutGrantRequest,
    ) -> Result<PutGrantResponse, PutGrantError>;

    async fn revoke_grant(
        &self,
        context: lenso::Ctx<'_>,
        request: RevokeGrantRequest,
    ) -> Result<RevokeGrantResponse, RevokeGrantError>;
}
