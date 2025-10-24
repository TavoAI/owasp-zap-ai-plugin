package com.tavoai.zap.ai.model;

/**
 * Enumeration of threat severity levels.
 */
public enum ThreatSeverity {

    /**
     * Informational finding, no immediate risk.
     */
    INFO("Info"),

    /**
     * Low severity threat, minimal risk.
     */
    LOW("Low"),

    /**
     * Medium severity threat, moderate risk.
     */
    MEDIUM("Medium"),

    /**
     * High severity threat, significant risk.
     */
    HIGH("High"),

    /**
     * Critical severity threat, immediate action required.
     */
    CRITICAL("Critical");

    private final String displayName;

    ThreatSeverity(String displayName) {
        this.displayName = displayName;
    }

    /**
     * Get the display name for this severity level.
     *
     * @return display name
     */
    public String getDisplayName() {
        return displayName;
    }

    /**
     * Get the numeric value for sorting (higher = more severe).
     *
     * @return numeric value
     */
    public int getNumericValue() {
        return ordinal();
    }

    @Override
    public String toString() {
        return displayName;
    }
}