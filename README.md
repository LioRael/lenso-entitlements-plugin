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
