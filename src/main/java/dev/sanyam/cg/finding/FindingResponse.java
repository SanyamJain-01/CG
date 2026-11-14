package dev.sanyam.cg.finding;

import dev.sanyam.cg.ai.AiExplanation;
import java.util.UUID;

/**
 * Grouped so clients can't confuse what the scanner said (source, evidence) with what the LLM added
 * (aiExplanation, null when no LLM ran).
 */
public record FindingResponse(UUID id, Source source, Location location, Evidence evidence, Ai aiExplanation) {

    public record Source(String tool, String ruleId, Severity severity) {
    }

    public record Location(String file, int startLine, int endLine) {
    }

    public record Evidence(String snippet, String message) {
    }

    public record Ai(String generatedBy, String promptVersion, String disclaimer, String risk, String fix,
                     boolean likelyFalsePositive) {
    }

    public static final String DISCLAIMER = "AI-generated, may be wrong. Check it against the code above.";

    public static FindingResponse from(Finding f, AiExplanation e) {
        Ai ai = e == null ? null : new Ai(e.getModel(), e.getPromptVersion(), DISCLAIMER, e.getRisk(), e.getFix(),
                e.isLikelyFalsePositive());
        return new FindingResponse(f.getId(),
                new Source(f.getTool(), f.getRuleId(), f.getSeverity()),
                new Location(f.getFilePath(), f.getStartLine(), f.getEndLine()),
                new Evidence(f.getSnippet(), f.getMessage()),
                ai);
    }
}
