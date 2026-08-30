//! Authoritative source for the Entitlements Capability contract.

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
pub struct ResolveEntitlementRequest {
    pub scope_kind: String,
    pub scope_id: String,
    pub subject: String,
    pub feature: String,
}

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct ResolveEntitlementResponse {
    pub granted: bool,
    pub grant_id: Nullable<String>,
    /// Positive base-10 int64 encoded as a portable string.
    pub limit: Nullable<String>,
    #[schemars(range(min = 0))]
    pub policy_revision: i64,
}

#[derive(lenso::DomainError)]
pub enum ResolveEntitlementError {
    InvalidRequest,
    Forbidden,
}

#[lenso::capability(
    id = "lenso.entitlements",
    major = 1,
    version = "1.0.0",
    portable = true,
    cross_lane_transfer = true
)]
pub trait Entitlements {
    async fn resolve_entitlement(
        &self,
        context: lenso::Ctx<'_>,
        request: ResolveEntitlementRequest,
    ) -> Result<ResolveEntitlementResponse, ResolveEntitlementError>;
}
