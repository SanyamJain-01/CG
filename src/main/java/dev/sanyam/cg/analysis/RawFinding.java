package dev.sanyam.cg.analysis;

import dev.sanyam.cg.finding.Severity;

/** One issue as a scanner reported it, before evidence is attached. File paths are relative to the scan root. */
public record RawFinding(String tool, String ruleId, Severity severity, String file, int startLine, int endLine,
                         String message) {
}
