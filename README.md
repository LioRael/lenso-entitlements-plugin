# Lenso Entitlements Plugin

This repository contains the removable vNext Entitlements deletion boundary.
It stores feature grants and optional limits, and exposes them as facts to a
target Plugin. The target remains the final authority for its operation.

The first slice provides:

- `lenso.entitlements@1` to resolve one exact scope, subject, and feature only
  for explicitly admitted target caller instances;
- `lenso.entitlements-admin@1` to put or revoke grants from explicitly admitted
  caller instances;
- private PostgreSQL state with monotonic per-scope policy revisions; and
- explicit operator-managed schema setup and upgrades.

An absent, revoked, or expired grant resolves to `granted = false`. The Plugin
does not inspect Usage Meter aggregates, infer plans, or mutate Access Control.
Grant expiry timestamps must resolve to whole microseconds so exact retries are
stable across PostgreSQL round trips.

## Release safety

All three crates are publishable so product Plugins can depend on the portable
Capability contracts without a Git source identity. The release workflow is
manually gated: a live run requires `live=true` plus `confirm=publish` on
`main`, and uses crates.io Trusted Publishing through GitHub OIDC.

For the first release, allocate the two Capability crate names before the
PostgreSQL Plugin so Cargo can verify the packaged dependency graph. Configure
each crates.io Trusted Publisher for owner `LioRael`, repository
`lenso-entitlements-plugin`, workflow `release-plz.yml`, with no environment.
