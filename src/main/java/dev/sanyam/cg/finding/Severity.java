package dev.sanyam.cg.finding;

import java.util.Locale;

/** Three levels for every tool. Declared most severe first, so sorting by ordinal puts HIGH on top. */
public enum Severity {
    HIGH, MEDIUM, LOW;

    /** Maps each scanner's own labels (Semgrep ERROR/WARNING/INFO, Bandit HIGH/MEDIUM/LOW) onto ours. */
    public static Severity normalize(String label) {
        return switch (label == null ? "" : label.toUpperCase(Locale.ROOT)) {
            case "CRITICAL", "HIGH", "ERROR" -> HIGH;
            case "MEDIUM", "WARNING" -> MEDIUM;
            default -> LOW;
        };
    }
}
