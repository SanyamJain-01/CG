package dev.sanyam.cg.analysis;

import java.util.List;

/** Findings from every scanner that ran, plus one line per scanner that couldn't run. */
public record AnalysisResult(List<RawFinding> findings, List<String> errors) {

    public static AnalysisResult empty() {
        return new AnalysisResult(List.of(), List.of());
    }
}
