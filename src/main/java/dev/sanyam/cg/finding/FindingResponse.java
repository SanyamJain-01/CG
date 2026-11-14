package dev.sanyam.cg.finding;

import java.util.UUID;

/** Grouped so clients can't confuse what the scanner said (source, evidence) with anything added later. */
public record FindingResponse(UUID id, Source source, Location location, Evidence evidence) {

    public record Source(String tool, String ruleId, Severity severity) {
    }

    public record Location(String file, int startLine, int endLine) {
    }

    public record Evidence(String snippet, String message) {
    }

    public static FindingResponse from(Finding f) {
        return new FindingResponse(f.getId(),
                new Source(f.getTool(), f.getRuleId(), f.getSeverity()),
                new Location(f.getFilePath(), f.getStartLine(), f.getEndLine()),
                new Evidence(f.getSnippet(), f.getMessage()));
    }
}
