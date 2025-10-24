package com.tavoai.zap.ai.model;

/**
 * Represents the result of an AI security scan.
 */
public class ScanResult {

    private final String scanId;
    private final String threatType;
    private final String severity;
    private final String url;
    private final String description;
    private final String evidence;
    private final long timestamp;

    /**
     * Constructor.
     *
     * @param scanId the scan identifier
     * @param threatType the type of threat detected
     * @param severity the severity level
     * @param url the URL where the issue was found
     * @param description the description of the finding
     * @param evidence the evidence supporting the finding
     */
    public ScanResult(String scanId, String threatType, String severity, String url,
                     String description, String evidence) {
        this.scanId = scanId;
        this.threatType = threatType;
        this.severity = severity;
        this.url = url;
        this.description = description;
        this.evidence = evidence;
        this.timestamp = System.currentTimeMillis();
    }

    /**
     * Get the scan identifier.
     *
     * @return scan ID
     */
    public String getScanId() {
        return scanId;
    }

    /**
     * Get the threat type.
     *
     * @return threat type
     */
    public String getThreatType() {
        return threatType;
    }

    /**
     * Get the severity level.
     *
     * @return severity
     */
    public String getSeverity() {
        return severity;
    }

    /**
     * Get the URL where the issue was found.
     *
     * @return URL
     */
    public String getUrl() {
        return url;
    }

    /**
     * Get the description of the finding.
     *
     * @return description
     */
    public String getDescription() {
        return description;
    }

    /**
     * Get the evidence supporting the finding.
     *
     * @return evidence
     */
    public String getEvidence() {
        return evidence;
    }

    /**
     * Get the timestamp when the result was created.
     *
     * @return timestamp
     */
    public long getTimestamp() {
        return timestamp;
    }

    @Override
    public String toString() {
        return String.format("ScanResult{scanId='%s', threatType='%s', severity='%s', url='%s'}",
                           scanId, threatType, severity, url);
    }
}