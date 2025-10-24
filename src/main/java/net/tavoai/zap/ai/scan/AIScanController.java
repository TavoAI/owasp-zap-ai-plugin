package net.tavoai.zap.ai.scan;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.core.scanner.Scanner;
import org.parosproxy.paros.core.scanner.ScannerParam;
import org.parosproxy.paros.core.scanner.Plugin;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.ascan.ScanPolicy;

import net.tavoai.zap.ai.rules.AIActiveScanRules;
import net.tavoai.zap.ai.rules.AIPassiveScanRules;
import net.tavoai.zap.ai.detector.AIDetector;
import net.tavoai.zap.ai.model.AIThreat;
import net.tavoai.zap.ai.model.ScanResult;

import java.util.List;
import java.util.ArrayList;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Controller for AI security scanning operations.
 *
 * Manages the coordination of AI-specific security scans,
 * including active and passive scanning with AI-aware rules.
 */
public class AIScanController {

    private static final Logger logger = LogManager.getLogger(AIScanController.class);

    private final AIDetector aiDetector;
    private final AIActiveScanRules activeScanRules;
    private final AIPassiveScanRules passiveScanRules;
    private final ExecutorService scanExecutor;
    private final List<ScanResult> scanResults;

    private volatile boolean scanning = false;

    /**
     * Constructor.
     */
    public AIScanController() {
        this.aiDetector = new AIDetector();
        this.activeScanRules = new AIActiveScanRules();
        this.passiveScanRules = new AIPassiveScanRules();
        this.scanExecutor = Executors.newFixedThreadPool(5);
        this.scanResults = new ArrayList<>();

        logger.info("AI Scan Controller initialized");
    }

    /**
     * Start an AI security scan on the specified target.
     *
     * @param targetUrl the URL to scan
     * @return scan ID for tracking progress
     */
    public String startScan(String targetUrl) {
        if (scanning) {
            throw new IllegalStateException("Scan already in progress");
        }

        String scanId = generateScanId();
        scanning = true;

        logger.info("Starting AI security scan for: {}", targetUrl);

        // Run scan asynchronously
        CompletableFuture.runAsync(() -> {
            try {
                performScan(scanId, targetUrl);
            } catch (Exception e) {
                logger.error("Error during AI scan: {}", e.getMessage(), e);
            } finally {
                scanning = false;
            }
        }, scanExecutor);

        return scanId;
    }

    /**
     * Perform the actual AI security scan.
     *
     * @param scanId the scan identifier
     * @param targetUrl the target URL
     */
    private void performScan(String scanId, String targetUrl) {
        logger.info("Performing AI security scan: {}", scanId);

        try {
            // Get site node for the target
            SiteNode siteNode = getSiteNode(targetUrl);
            if (siteNode == null) {
                logger.warn("No site node found for: {}", targetUrl);
                return;
            }

            // Perform passive scanning
            performPassiveScan(scanId, siteNode);

            // Perform active scanning
            performActiveScan(scanId, siteNode);

            // Generate final report
            generateScanReport(scanId);

            logger.info("AI security scan completed: {}", scanId);

        } catch (Exception e) {
            logger.error("Error performing AI scan {}: {}", scanId, e.getMessage(), e);
            recordScanError(scanId, e);
        }
    }

    /**
     * Perform passive AI scanning.
     *
     * @param scanId the scan identifier
     * @param siteNode the site node to scan
     */
    private void performPassiveScan(String scanId, SiteNode siteNode) {
        logger.debug("Performing passive AI scan: {}", scanId);

        try {
            // Get all HTTP messages for the site
            List<HttpMessage> messages = getHttpMessages(siteNode);

            for (HttpMessage message : messages) {
                // Run passive AI rules
                List<AIThreat> threats = passiveScanRules.scanMessage(message);

                for (AIThreat threat : threats) {
                    ScanResult result = new ScanResult(
                        scanId,
                        threat.getType().toString(),
                        threat.getSeverity().toString(),
                        message.getRequestHeader().getURI().toString(),
                        threat.getDescription(),
                        threat.getEvidence()
                    );
                    scanResults.add(result);
                }
            }

        } catch (Exception e) {
            logger.error("Error in passive AI scan: {}", e.getMessage(), e);
        }
    }

    /**
     * Perform active AI scanning.
     *
     * @param scanId the scan identifier
     * @param siteNode the site node to scan
     */
    private void performActiveScan(String scanId, SiteNode siteNode) {
        logger.debug("Performing active AI scan: {}", scanId);

        try {
            // Create AI-specific scan policy
            ScanPolicy scanPolicy = createAIScanPolicy();

            // Get scanner instance
            Scanner scanner = new Scanner(
                Model.getSingleton().getOptionsParam().getParamSet(ScannerParam.class),
                Model.getSingleton().getOptionsParam().getConnectionParam(),
                scanPolicy
            );

            // Configure scanner for AI testing
            configureAIScanner(scanner, siteNode);

            // Start the scan
            scanner.start(siteNode);

            // Wait for completion (with timeout)
            waitForScanCompletion(scanner, 300000); // 5 minutes timeout

        } catch (Exception e) {
            logger.error("Error in active AI scan: {}", e.getMessage(), e);
        }
    }

    /**
     * Create AI-specific scan policy.
     *
     * @return configured scan policy
     */
    private ScanPolicy createAIScanPolicy() {
        ScanPolicy policy = new ScanPolicy();

        // Configure policy for AI testing
        // Enable AI-specific rules, disable generic rules that don't apply to AI
        policy.setDefaultThreshold(Plugin.AlertThreshold.MEDIUM);
        policy.setDefaultStrength(Plugin.AttackStrength.MEDIUM);

        return policy;
    }

    /**
     * Configure scanner for AI testing.
     *
     * @param scanner the scanner to configure
     * @param siteNode the site node
     */
    private void configureAIScanner(Scanner scanner, SiteNode siteNode) {
        // TODO: Add AI-specific scan rules - methods not available in ZAP 2.16.0
        // scanner.addScanRule(activeScanRules.getPromptInjectionRule());
        // scanner.addScanRule(activeScanRules.getModelManipulationRule());
        // scanner.addScanRule(activeScanRules.getDataExfiltrationRule());
        // scanner.addScanRule(activeScanRules.getRateLimitBypassRule());

        // Configure scan scope
        scanner.setScanChildren(true);
        scanner.setJustScanInScope(true);
    }

    /**
     * Wait for scan completion with timeout.
     *
     * @param scanner the scanner
     * @param timeoutMs timeout in milliseconds
     */
    private void waitForScanCompletion(Scanner scanner, long timeoutMs) {
        long startTime = System.currentTimeMillis();

        // TODO: Check scanner status - isRunning() method not available in ZAP 2.16.0
        // For now, just wait for timeout
        try {
            Thread.sleep(Math.min(timeoutMs, 30000)); // Wait up to 30 seconds
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        logger.warn("Scan timeout reached, stopping scan");
        scanner.stop();
    }

    /**
     * Generate scan report.
     *
     * @param scanId the scan identifier
     */
    private void generateScanReport(String scanId) {
        logger.info("Generating scan report for: {}", scanId);

        // Filter results for this scan
        List<ScanResult> scanSpecificResults = scanResults.stream()
            .filter(result -> scanId.equals(result.getScanId()))
            .toList();

        // Generate report
        AIScanReport report = new AIScanReport(scanId, scanSpecificResults);
        report.generate();

        logger.info("Scan report generated: {} findings", scanSpecificResults.size());
    }

    /**
     * Record scan error.
     *
     * @param scanId the scan identifier
     * @param error the error
     */
    private void recordScanError(String scanId, Exception error) {
        ScanResult errorResult = new ScanResult(
            scanId,
            "scan_error",
            "info",
            "N/A",
            "Scan error: " + error.getMessage(),
            error.toString()
        );
        scanResults.add(errorResult);
    }

    /**
     * Get HTTP messages for a site node.
     *
     * @param siteNode the site node
     * @return list of HTTP messages
     */
    private List<HttpMessage> getHttpMessages(SiteNode siteNode) {
        List<HttpMessage> messages = new ArrayList<>();

        // Recursively collect messages from site tree
        collectMessages(siteNode, messages);

        return messages;
    }

    /**
     * Recursively collect HTTP messages from site tree.
     *
     * @param node the current node
     * @param messages the message list to populate
     */
    private void collectMessages(SiteNode node, List<HttpMessage> messages) {
        // Add message if this node has one
        if (node.getHistoryReference() != null) {
            try {
                HttpMessage msg = node.getHistoryReference().getHttpMessage();
                if (msg != null) {
                    messages.add(msg);
                }
            } catch (Exception e) {
                logger.debug("Could not get message for node: {}", e.getMessage());
            }
        }

        // Recurse on children
        for (int i = 0; i < node.getChildCount(); i++) {
            collectMessages((SiteNode) node.getChildAt(i), messages);
        }
    }

    /**
     * Get site node for URL.
     *
     * @param url the URL
     * @return site node or null if not found
     */
    private SiteNode getSiteNode(String url) {
        try {
            return Model.getSingleton().getSession().getSiteTree().findNode(new org.apache.commons.httpclient.URI(url));
        } catch (Exception e) {
            logger.warn("Could not find site node for: {}", url);
            return null;
        }
    }

    /**
     * Generate unique scan ID.
     *
     * @return scan ID
     */
    private String generateScanId() {
        return "ai_scan_" + System.currentTimeMillis() + "_" + (int)(Math.random() * 1000);
    }

    /**
     * Check if scanning is in progress.
     *
     * @return true if scanning
     */
    public boolean isScanning() {
        return scanning;
    }

    /**
     * Get scan results for a specific scan.
     *
     * @param scanId the scan identifier
     * @return list of scan results
     */
    public List<ScanResult> getScanResults(String scanId) {
        return scanResults.stream()
            .filter(result -> scanId.equals(result.getScanId()))
            .toList();
    }

    /**
     * Get all scan results.
     *
     * @return list of all scan results
     */
    public List<ScanResult> getAllScanResults() {
        return new ArrayList<>(scanResults);
    }

    /**
     * Shutdown the scan controller.
     */
    public void shutdown() {
        logger.info("Shutting down AI Scan Controller");
        scanExecutor.shutdown();

        // Close detector resources
        if (aiDetector != null) {
            aiDetector.close();
        }
    }

    /**
     * Configure backend integration settings.
     *
     * @param apiKey the API key for backend authentication
     * @param backendUrl the backend URL (optional, defaults to production)
     * @param submitSuspicious whether to submit suspicious content
     * @param submitBorderline whether to submit borderline content
     */
    public void configureBackend(String apiKey, String backendUrl, boolean submitSuspicious, boolean submitBorderline) {
        // Configure the detector with backend settings
        aiDetector.configureBackend(apiKey, backendUrl, submitSuspicious, submitBorderline);

        // Configure scan rules
        activeScanRules.configureBackend(apiKey, backendUrl, submitSuspicious, submitBorderline);
        passiveScanRules.configureBackend(apiKey, backendUrl, submitSuspicious, submitBorderline);

        logger.info("Backend integration configured for scan controller");
    }

    /**
     * Get the AI detector.
     *
     * @return the AI detector
     */
    public AIDetector getDetector() {
        return aiDetector;
    }
}