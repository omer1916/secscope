-- Initial schema. Applied once; PRAGMA user_version tracks the applied migration.

CREATE TABLE scans (
    id                     TEXT PRIMARY KEY,
    created_at             TEXT NOT NULL,            -- ISO-8601 UTC
    finished_at            TEXT,
    status                 TEXT NOT NULL DEFAULT 'running',
    target_kind            TEXT NOT NULL,
    target                 TEXT NOT NULL,
    profile                TEXT NOT NULL,
    scope_accepted_at      TEXT,                     -- SPEC §4.5: consent is recorded
    config_json            TEXT NOT NULL,
    scores_json            TEXT,
    tool_versions_json     TEXT,
    app_version            TEXT NOT NULL
);

CREATE TABLE findings (
    scan_id      TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    finding_id   TEXT NOT NULL,
    rule_id      TEXT NOT NULL,
    module       TEXT NOT NULL,
    category     TEXT NOT NULL,
    severity     TEXT NOT NULL,
    confidence   TEXT NOT NULL,
    data_json    TEXT NOT NULL,
    PRIMARY KEY (scan_id, finding_id)
);
CREATE INDEX findings_by_rule ON findings(rule_id);
CREATE INDEX findings_by_id ON findings(finding_id);

CREATE TABLE module_runs (
    scan_id      TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    module       TEXT NOT NULL,
    status       TEXT NOT NULL,                      -- ok | failed | cancelled | timeout | skipped
    reason       TEXT,
    duration_s   REAL,
    PRIMARY KEY (scan_id, module)
);

-- False-positive suppressions (SPEC §11.2.4): a reason is mandatory.
CREATE TABLE suppressions (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id   TEXT,
    rule_id      TEXT,
    reason       TEXT NOT NULL CHECK (length(trim(reason)) > 0),
    created_at   TEXT NOT NULL,
    CHECK (finding_id IS NOT NULL OR rule_id IS NOT NULL)
);
