CREATE TABLE entitlement_scopes (
    scope_kind text NOT NULL,
    scope_id text NOT NULL,
    policy_revision bigint NOT NULL DEFAULT 0 CHECK (policy_revision >= 0),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (scope_kind, scope_id)
);

CREATE TABLE entitlement_grants (
    grant_id text PRIMARY KEY,
    scope_kind text NOT NULL,
    scope_id text NOT NULL,
    subject text NOT NULL,
    feature_key text NOT NULL,
    limit_value bigint CHECK (limit_value > 0),
    expires_at timestamptz,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    FOREIGN KEY (scope_kind, scope_id)
        REFERENCES entitlement_scopes(scope_kind, scope_id),
    UNIQUE (scope_kind, scope_id, subject, feature_key)
);

CREATE INDEX entitlement_grants_resolution_idx
    ON entitlement_grants(scope_kind, scope_id, subject, feature_key)
    WHERE revoked_at IS NULL;
