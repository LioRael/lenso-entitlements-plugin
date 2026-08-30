# vNext Entitlements Plugin card

## Owner and deletion boundary

`lenso-entitlements-postgres-plugin` owns feature grants, optional numeric
limits, expiry, revocation, and monotonic scope revisions. Removing its Plugin
Instance and owned schema removes all Entitlements behavior and state.

## Roles

- Provides `lenso.entitlements@1` as a fact query only to exact App-admitted
  target caller instances. A positive result is not final authorization; the
  target Plugin still validates actor, resource state, and operation-specific
  policy.
- Provides `lenso.entitlements-admin@1` only to exact App-admitted caller
  instances.
- Requires `lenso.secrets@1` during activation for its PostgreSQL URL.

## First observable behavior

An admitted administrator puts or revokes one grant. Every material mutation
advances that scope's revision in the same transaction. Querying an absent,
revoked, or expired grant returns a stable default-deny fact.

Usage events and aggregates belong to Usage Meter. Roles and permissions belong
to Access Control. Product checkout and billing-provider synchronization are
future Plugins that may call Entitlements Admin through explicit bindings.
