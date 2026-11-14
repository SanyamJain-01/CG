-- AI output is stored apart from scanner output, with the model and prompt version that produced it.
ALTER TABLE scans ADD COLUMN llm_status TEXT CHECK (llm_status IN ('DONE', 'SKIPPED', 'FAILED'));

CREATE TABLE ai_explanations (
    id                    UUID PRIMARY KEY,
    finding_id            UUID NOT NULL UNIQUE REFERENCES findings(id) ON DELETE CASCADE,
    model                 TEXT NOT NULL,
    prompt_version        TEXT NOT NULL,
    risk                  TEXT NOT NULL,
    fix                   TEXT NOT NULL,
    likely_false_positive BOOLEAN NOT NULL,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);
