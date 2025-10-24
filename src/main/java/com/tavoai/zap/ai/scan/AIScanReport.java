package com.tavoai.zap.ai.scan;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.tavoai.zap.ai.model.ScanResult;

import java.util.List;
import java.util.Map;
import java.util.HashMap;
import java.util.stream.Collectors;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Paths;

/**
 * Generates reports for AI security scans.
 */
public class AIScanReport {

    private static final Logger logger = LogManager.getLogger(AIScanReport.class);

    private final String scanId;
    private final List<ScanResult> results;
    private final long startTime;
    private final long endTime;

    /**
     * Constructor.
     *
     * @param scanId the scan identifier
     * @param results the scan results
     */
    public AIScanReport(String scanId, List<ScanResult> results) {
        this.scanId = scanId;
        this.results = results;
        this.startTime = System.currentTimeMillis();
        this.endTime = System.currentTimeMillis();
    }

    /**
     * Generate the scan report.
     */
    public void generate() {
        logger.info("Generating AI scan report for: {}", scanId);

        try {
            // Generate summary statistics
            Map<String, Long> threatCounts = results.stream()
                .collect(Collectors.groupingBy(ScanResult::getThreatType, Collectors.counting()));

            Map<String, Long> severityCounts = results.stream()
                .collect(Collectors.groupingBy(ScanResult::getSeverity, Collectors.counting()));

            // Generate HTML report
            String htmlReport = generateHtmlReport(threatCounts, severityCounts);

            // Save report to file
            saveReport(htmlReport);

            // Log summary
            logSummary(threatCounts, severityCounts);

        } catch (Exception e) {
            logger.error("Error generating scan report: {}", e.getMessage(), e);
        }
    }

    /**
     * Generate HTML report content.
     *
     * @param threatCounts threat type counts
     * @param severityCounts severity level counts
     * @return HTML report content
     */
    private String generateHtmlReport(Map<String, Long> threatCounts, Map<String, Long> severityCounts) {
        StringBuilder html = new StringBuilder();

        html.append("<!DOCTYPE html>\n");
        html.append("<html>\n");
        html.append("<head>\n");
        html.append("    <title>AI Security Scan Report - ").append(scanId).append("</title>\n");
        html.append("    <style>\n");
        html.append("        body { font-family: Arial, sans-serif; margin: 20px; }\n");
        html.append("        .header { background-color: #f8f9fa; padding: 20px; border-radius: 5px; margin-bottom: 20px; }\n");
        html.append("        .summary { background-color: #e9ecef; padding: 15px; border-radius: 5px; margin-bottom: 20px; }\n");
        html.append("        .results { margin-top: 20px; }\n");
        html.append("        .result-item { border: 1px solid #ddd; padding: 10px; margin-bottom: 10px; border-radius: 5px; }\n");
        html.append("        .severity-critical { border-left: 5px solid #dc3545; }\n");
        html.append("        .severity-high { border-left: 5px solid #fd7e14; }\n");
        html.append("        .severity-medium { border-left: 5px solid #ffc107; }\n");
        html.append("        .severity-low { border-left: 5px solid #28a745; }\n");
        html.append("        .severity-info { border-left: 5px solid #6c757d; }\n");
        html.append("        table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }\n");
        html.append("        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }\n");
        html.append("        th { background-color: #f8f9fa; }\n");
        html.append("    </style>\n");
        html.append("</head>\n");
        html.append("<body>\n");

        // Header
        html.append("    <div class='header'>\n");
        html.append("        <h1>AI Security Scan Report</h1>\n");
        html.append("        <p><strong>Scan ID:</strong> ").append(scanId).append("</p>\n");
        html.append("        <p><strong>Scan Date:</strong> ").append(new java.util.Date(startTime)).append("</p>\n");
        html.append("        <p><strong>Duration:</strong> ").append(endTime - startTime).append(" ms</p>\n");
        html.append("    </div>\n");

        // Summary
        html.append("    <div class='summary'>\n");
        html.append("        <h2>Summary</h2>\n");
        html.append("        <p><strong>Total Findings:</strong> ").append(results.size()).append("</p>\n");

        html.append("        <h3>Findings by Threat Type</h3>\n");
        html.append("        <table>\n");
        html.append("            <tr><th>Threat Type</th><th>Count</th></tr>\n");
        for (Map.Entry<String, Long> entry : threatCounts.entrySet()) {
            html.append("            <tr><td>").append(entry.getKey()).append("</td><td>").append(entry.getValue()).append("</td></tr>\n");
        }
        html.append("        </table>\n");

        html.append("        <h3>Findings by Severity</h3>\n");
        html.append("        <table>\n");
        html.append("            <tr><th>Severity</th><th>Count</th></tr>\n");
        for (Map.Entry<String, Long> entry : severityCounts.entrySet()) {
            html.append("            <tr><td>").append(entry.getKey()).append("</td><td>").append(entry.getValue()).append("</td></tr>\n");
        }
        html.append("        </table>\n");
        html.append("    </div>\n");

        // Detailed Results
        html.append("    <div class='results'>\n");
        html.append("        <h2>Detailed Findings</h2>\n");

        for (ScanResult result : results) {
            String severityClass = "severity-" + result.getSeverity().toLowerCase();
            html.append("        <div class='result-item ").append(severityClass).append("'>\n");
            html.append("            <h3>").append(result.getThreatType()).append(" (").append(result.getSeverity()).append(")</h3>\n");
            html.append("            <p><strong>URL:</strong> ").append(result.getUrl()).append("</p>\n");
            html.append("            <p><strong>Description:</strong> ").append(result.getDescription()).append("</p>\n");
            html.append("            <p><strong>Evidence:</strong> ").append(result.getEvidence()).append("</p>\n");
            html.append("        </div>\n");
        }

        html.append("    </div>\n");
        html.append("</body>\n");
        html.append("</html>\n");

        return html.toString();
    }

    /**
     * Save the report to a file.
     *
     * @param htmlReport the HTML report content
     */
    private void saveReport(String htmlReport) {
        try {
            String fileName = "ai_scan_report_" + scanId + ".html";
            String filePath = Paths.get(System.getProperty("user.home"), "zap_reports", fileName).toString();

            // Create reports directory if it doesn't exist
            java.nio.file.Path reportsDir = Paths.get(System.getProperty("user.home"), "zap_reports");
            java.nio.file.Files.createDirectories(reportsDir);

            // Write report file
            try (FileWriter writer = new FileWriter(filePath)) {
                writer.write(htmlReport);
            }

            logger.info("Report saved to: {}", filePath);

        } catch (IOException e) {
            logger.error("Error saving report: {}", e.getMessage(), e);
        }
    }

    /**
     * Log summary information.
     *
     * @param threatCounts threat type counts
     * @param severityCounts severity level counts
     */
    private void logSummary(Map<String, Long> threatCounts, Map<String, Long> severityCounts) {
        logger.info("AI Scan Report Summary for {}:", scanId);
        logger.info("Total findings: {}", results.size());
        logger.info("Threat types: {}", threatCounts);
        logger.info("Severity levels: {}", severityCounts);
    }

    /**
     * Get the scan ID.
     *
     * @return scan ID
     */
    public String getScanId() {
        return scanId;
    }

    /**
     * Get the scan results.
     *
     * @return list of scan results
     */
    public List<ScanResult> getResults() {
        return results;
    }
}