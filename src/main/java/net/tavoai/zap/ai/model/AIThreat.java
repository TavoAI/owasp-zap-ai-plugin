package net.tavoai.zap.ai.model;

/**
 * Represents an AI security threat detected during scanning.
 */
public class AIThreat {

    private final ThreatType type;
    private final ThreatSeverity severity;
    private final String description;
    private final String evidence;
    private final String url;
    private final long timestamp;

    /**
     * Constructor.
     *
     * @param type the threat type
     * @param severity the threat severity
     * @param description the threat description
     * @param evidence the evidence supporting the threat detection
     * @param url the URL where the threat was detected
     */
    public AIThreat(ThreatType type, ThreatSeverity severity, String description,
                   String evidence, String url) {
        this.type = type;
        this.severity = severity;
        this.description = description;
        this.evidence = evidence;
        this.url = url;
        this.timestamp = System.currentTimeMillis();
    }

    /**
     * Get the threat type.
     *
     * @return threat type
     */
    public ThreatType getType() {
        return type;
    }

    /**
     * Get the threat severity.
     *
     * @return threat severity
     */
    public ThreatSeverity getSeverity() {
        return severity;
    }

    /**
     * Get the threat description.
     *
     * @return description
     */
    public String getDescription() {
        return description;
    }

    /**
     * Get the evidence for this threat.
     *
     * @return evidence
     */
    public String getEvidence() {
        return evidence;
    }

    /**
     * Get the URL where the threat was detected.
     *
     * @return URL
     */
    public String getUrl() {
        return url;
    }

    /**
     * Get the timestamp when the threat was detected.
     *
     * @return timestamp
     */
    public long getTimestamp() {
        return timestamp;
    }

    @Override
    public String toString() {
        return String.format("AIThreat{type=%s, severity=%s, description='%s', url='%s'}",
                           type, severity, description, url);
    }
}