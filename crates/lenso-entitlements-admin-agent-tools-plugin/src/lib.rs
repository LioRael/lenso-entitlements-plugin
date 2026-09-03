//! Agent-facing Tools over an explicitly bound Entitlements Admin capability.

use lenso::prelude::*;
use lenso_capability_agent_tool_provider::{
    self as tool_contract, CatalogRequest, CatalogResponse, ContentType, ExecuteError,
    ExecuteRequest, ExecuteResponse, ExecutionFailedPayload, ToolDefinition, ToolExecutionClass,
};
use lenso_capability_entitlements_admin::{
    self as admin, ListGrantsRequest, PutGrantRequest, RevokeGrantRequest,
};
use lenso_kernel::RuntimeFailure;
use serde::{Serialize, de::DeserializeOwned};

pub const LIST_GRANTS_TOOL: &str = "entitlements_admin_list_grants";
pub const PUT_GRANT_TOOL: &str = "entitlements_admin_put_grant";
pub const REVOKE_GRANT_TOOL: &str = "entitlements_admin_revoke_grant";

#[lenso::plugin]
#[derive(Clone, Debug)]
struct EntitlementsAdminAgentToolsPlugin {
    admin: Port<admin::EntitlementsAdminClient>,
}

#[lenso::provides(tool_contract::ToolProvider)]
impl EntitlementsAdminAgentToolsPlugin {
    fn catalog(
        &self,
        _context: Ctx,
        _request: CatalogRequest,
    ) -> impl std::future::Future<Output = PluginResult<CatalogResponse, tool_contract::CatalogError>>
    {
        let _ = self;
        futures::future::ready(Ok(CatalogResponse {
            tools: tool_definitions(),
        }))
    }

    async fn execute(
        &self,
        context: Ctx,
        request: ExecuteRequest,
    ) -> PluginResult<ExecuteResponse, ExecuteError> {
        match request.name.as_str() {
            LIST_GRANTS_TOOL => {
                let arguments = decode::<ListGrantsRequest>(&request)?;
                match self
                    .admin
                    .list_grants_with_context(context, arguments)
                    .await
                {
                    Ok(response) => success(LIST_GRANTS_TOOL, &response),
                    Err(admin::EntitlementsAdminListGrantsInvocationError::Domain(error)) => {
                        Err(PluginError::domain(map_list_error(&error)))
                    }
                    Err(admin::EntitlementsAdminListGrantsInvocationError::Runtime(error)) => {
                        Err(PluginError::runtime(error))
                    }
                }
            }
            PUT_GRANT_TOOL => {
                let arguments = decode::<PutGrantRequest>(&request)?;
                match self.admin.put_grant_with_context(context, arguments).await {
                    Ok(response) => success(PUT_GRANT_TOOL, &response),
                    Err(admin::EntitlementsAdminPutGrantInvocationError::Domain(error)) => {
                        Err(PluginError::domain(map_put_error(&error)))
                    }
                    Err(admin::EntitlementsAdminPutGrantInvocationError::Runtime(error)) => {
                        Err(PluginError::runtime(error))
                    }
                }
            }
            REVOKE_GRANT_TOOL => {
                let arguments = decode::<RevokeGrantRequest>(&request)?;
                match self
                    .admin
                    .revoke_grant_with_context(context, arguments)
                    .await
                {
                    Ok(response) => success(REVOKE_GRANT_TOOL, &response),
                    Err(admin::EntitlementsAdminRevokeGrantInvocationError::Domain(error)) => {
                        Err(PluginError::domain(map_revoke_error(&error)))
                    }
                    Err(admin::EntitlementsAdminRevokeGrantInvocationError::Runtime(error)) => {
                        Err(PluginError::runtime(error))
                    }
                }
            }
            _ => Err(PluginError::domain(ExecuteError::NotFound)),
        }
    }
}

fn tool_definitions() -> Vec<ToolDefinition> {
    vec![
        tool(
            LIST_GRANTS_TOOL,
            "List grants in one exact entitlement scope with optional subject, feature, and effective-status filters.",
            include_str!(
                "../../lenso-capability-entitlements-admin/schemas/list-grants-request.schema.json"
            ),
            ToolExecutionClass::ParallelSafe,
        ),
        tool(
            PUT_GRANT_TOOL,
            "Create or replace one entitlement grant and return the scope policy revision.",
            include_str!(
                "../../lenso-capability-entitlements-admin/schemas/put-grant-request.schema.json"
            ),
            ToolExecutionClass::Exclusive,
        ),
        tool(
            REVOKE_GRANT_TOOL,
            "Revoke one entitlement grant by id and return the scope policy revision.",
            include_str!(
                "../../lenso-capability-entitlements-admin/schemas/revoke-grant-request.schema.json"
            ),
            ToolExecutionClass::Exclusive,
        ),
    ]
}

fn tool(
    name: &str,
    description: &str,
    schema: &str,
    execution: ToolExecutionClass,
) -> ToolDefinition {
    let schema: serde_json::Value =
        serde_json::from_str(schema).expect("Entitlements Admin Tool schema must be valid JSON");
    ToolDefinition {
        name: name.to_owned(),
        description: description.to_owned(),
        input_schema_json: schema
            .to_string()
            .try_into()
            .expect("Entitlements Admin Tool schema must remain valid JSON"),
        execution,
    }
}

fn decode<T: DeserializeOwned>(request: &ExecuteRequest) -> PluginResult<T, ExecuteError> {
    serde_json::from_str(request.arguments_json.as_str())
        .map_err(|_| PluginError::domain(ExecuteError::InvalidArguments))
}

fn success<T: Serialize>(
    tool_name: &str,
    response: &T,
) -> PluginResult<ExecuteResponse, ExecuteError> {
    let content = serde_json::to_string_pretty(response).map_err(|error| {
        PluginError::runtime(RuntimeFailure::PluginFailure {
            detail: format!("Entitlements Admin Tool could not serialize its response: {error}"),
        })
    })?;
    Ok(ExecuteResponse {
        content_blocks: None,
        content,
        content_type: ContentType::Text,
        metadata_json: serde_json::json!({ "tool": tool_name })
            .to_string()
            .try_into()
            .expect("Entitlements Admin Tool metadata must be valid JSON"),
    })
}

fn map_list_error(error: &admin::ListGrantsError) -> ExecuteError {
    match error {
        admin::ListGrantsError::InvalidQuery => ExecuteError::InvalidArguments,
        admin::ListGrantsError::Forbidden => ExecuteError::PermissionDenied,
        admin::ListGrantsError::Unknown(_) => rejected("unknown_domain_error"),
    }
}

fn map_put_error(error: &admin::PutGrantError) -> ExecuteError {
    match error {
        admin::PutGrantError::InvalidGrant => ExecuteError::InvalidArguments,
        admin::PutGrantError::Forbidden => ExecuteError::PermissionDenied,
        admin::PutGrantError::Unknown(_) => rejected("unknown_domain_error"),
    }
}

fn map_revoke_error(error: &admin::RevokeGrantError) -> ExecuteError {
    match error {
        admin::RevokeGrantError::InvalidGrant => ExecuteError::InvalidArguments,
        admin::RevokeGrantError::NotFound => ExecuteError::NotFound,
        admin::RevokeGrantError::Forbidden => ExecuteError::PermissionDenied,
        admin::RevokeGrantError::Unknown(_) => rejected("unknown_domain_error"),
    }
}

fn rejected(reason_code: &str) -> ExecuteError {
    ExecuteError::ExecutionFailed {
        payload: ExecutionFailedPayload {
            reason_code: reason_code.to_owned(),
            message: "Entitlements Admin rejected the requested operation.".to_owned(),
            details_json: serde_json::json!({ "domain_error": reason_code })
                .to_string()
                .try_into()
                .expect("Entitlements Admin Tool error metadata must be valid JSON"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(name: &str, arguments: &str) -> ExecuteRequest {
        ExecuteRequest {
            name: name.to_owned(),
            arguments_json: arguments.try_into().unwrap(),
        }
    }

    #[test]
    fn descriptor_is_a_removable_entitlements_admin_only_adapter() {
        let descriptor: serde_json::Value = serde_json::from_str(PLUGIN_DESCRIPTOR_JSON).unwrap();
        assert_eq!(
            descriptor["plugin_id"],
            "lenso.entitlements.admin.agent-tools"
        );
        assert_eq!(
            descriptor["provided_capabilities"][0]["capability_id"],
            "lenso.agent.tool-provider@2"
        );
        let required = descriptor["required_capabilities"].as_array().unwrap();
        assert_eq!(required.len(), 1);
        assert_eq!(required[0]["capability_id"], "lenso.entitlements-admin@1");
    }

    #[test]
    fn catalog_has_one_read_and_two_mutations() {
        let tools = tool_definitions();
        assert_eq!(tools.len(), 3);
        assert_eq!(
            tools
                .iter()
                .filter(|tool| tool.execution == ToolExecutionClass::ParallelSafe)
                .count(),
            1
        );
        assert_eq!(
            tools
                .iter()
                .filter(|tool| tool.execution == ToolExecutionClass::Exclusive)
                .count(),
            2
        );
    }

    #[test]
    fn list_request_is_exact_and_domain_failures_remain_distinct() {
        let list = decode::<ListGrantsRequest>(&request(
            LIST_GRANTS_TOOL,
            r#"{"scope_kind":"organization","scope_id":"org_acme","subject":null,"feature":null,"status":"active","limit":50,"cursor":null}"#,
        ))
        .unwrap();
        assert_eq!(list.limit, 50);
        assert!(
            decode::<ListGrantsRequest>(&request(
                LIST_GRANTS_TOOL,
                r#"{"scope_kind":"organization","scope_id":"org_acme","subject":null,"feature":null,"status":"active","limit":"50","cursor":null}"#,
            ))
            .is_err()
        );
        assert_eq!(
            map_revoke_error(&admin::RevokeGrantError::NotFound),
            ExecuteError::NotFound
        );
        assert_eq!(
            map_list_error(&admin::ListGrantsError::Forbidden),
            ExecuteError::PermissionDenied
        );
    }
}
