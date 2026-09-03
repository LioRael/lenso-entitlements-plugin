# Entitlements Admin Agent Tools Plugin card

## Owner and deletion boundary

`lenso-entitlements-admin-agent-tools-plugin` is a private, stateless adapter.
Removing it removes only the Console Agent's Entitlements management Tools; it
does not remove grants or change the PostgreSQL Plugin's authority.

## Roles

- Provides `lenso.agent.tool-provider@2` in the `tool-providers` root slot.
- Requires exactly `lenso.entitlements-admin@1`.
- Exposes bounded `list_grants`, `put_grant`, and `revoke_grant` operations as
  one parallel-safe read Tool and two exclusive mutation Tools.

## Authority boundary

The adapter decodes Tool arguments, forwards the invocation context, preserves
domain errors, and serializes the response. The bound Entitlements provider
still performs final caller authorization and owns all grant state. The adapter
does not expose `lenso.entitlements@1/resolve`, Usage Meter data, Billing data,
or direct database access.
