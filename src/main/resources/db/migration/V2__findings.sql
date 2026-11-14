-- Scanner output. AI explanations get their own table later, so the two are never mixed up.
ALTER TABLE scans ADD COLUMN tool_errors TEXT;

CREATE TABLE findings (
    id          UUID PRIMARY KEY,
    scan_id     UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    tool        TEXT NOT NULL,
    rule_id     TEXT NOT NULL,
    severity    TEXT NOT NULL CHECK (severity IN ('HIGH','MEDIUM','LOW')),
    file_path   TEXT NOT NULL,
    start_line  INT  NOT NULL CHECK (start_line >= 1),
    end_line    INT  NOT NULL,
    message     TEXT NOT NULL,
    snippet     TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    CHECK (end_line >= start_line),
    UNIQUE (scan_id, fingerprint)
);

CREATE INDEX findings_scan_severity ON findings (scan_id, severity);
