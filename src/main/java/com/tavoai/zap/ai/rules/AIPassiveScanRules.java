package com.tavoai.zap.ai.rules;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.model.TechSet;

import com.tavoai.zap.ai.detector.AIDetector;
import com.tavoai.zap.ai.model.AIThreat;
import com.tavoai.zap.ai.client.BackendClient;

import java.util.List;

/**
 * Passive scan rules for AI security testing.
 *
 * These rules analyze HTTP traffic without sending additional requests,
 * focusing on detecting AI-specific security issues in existing traffic.
 */
public class AIPassiveScanRules {

    private static final Logger logger = LogManager.getLogger(AIPassiveScanRules.class);

    private final AIDetector aiDetector;
    private BackendClient backendClient;

    /**
     * Constructor.
     */
    public AIPassiveScanRules() {
        this.aiDetector = new AIDetector();
    }

    /**
     * Scan an HTTP message for AI security issues.
     *
     * @param msg the HTTP message to scan
     * @return list of detected threats
     */
    public List<AIThreat> scanMessage(HttpMessage msg) {
        logger.debug("Scanning message for AI threats: {}", msg.getRequestHeader().getURI());

        try {
            return aiDetector.analyzeMessage(msg);
        } catch (Exception e) {
            logger.error("Error scanning message: {}", e.getMessage(), e);
            return List.of(); // Return empty list on error
        }
    }

    public void scanHttpRequestSend(HttpMessage msg, int id) {
        // Analyze request for AI threats
        List<AIThreat> threats = scanMessage(msg);
        reportThreats(threats, msg);
    }

    public void scanHttpResponseReceive(HttpMessage msg, int id, Object source) {
        // Analyze response for AI threats
        List<AIThreat> threats = scanMessage(msg);
        reportThreats(threats, msg);
    }

    /**
     * Report detected threats as alerts.
     */
    private void reportThreats(List<AIThreat> threats, HttpMessage msg) {
        for (AIThreat threat : threats) {
            try {
                // Create alert using ZAP's alert system
                org.parosproxy.paros.core.scanner.Alert alert = new org.parosproxy.paros.core.scanner.Alert(
                    getId(),
                    mapSeverityToRisk(threat.getSeverity().toString()),
                    org.parosproxy.paros.core.scanner.Alert.CONFIDENCE_MEDIUM,
                    "AI Security: " + threat.getType().getDisplayName()
                );
                alert.setDetail(threat.getDescription(), threat.getEvidence(),
                    msg.getRequestHeader().getURI().toString(),
                    "", "", getSolutionForThreat(threat.getType().toString()),
                    getReferenceForThreat(threat.getType().toString()), "", 0, 0, msg);

                // Raise the alert
                org.parosproxy.paros.control.Control.getSingleton()
                    .getExtensionLoader()
                    .getExtension(org.zaproxy.zap.extension.alert.ExtensionAlert.class)
                    .alertFound(alert, msg.getHistoryRef());
            } catch (Exception e) {
                logger.error("Failed to create alert for threat: {}", threat.getType(), e);
            }
        }
    }

    /**
     * Map threat severity to ZAP risk level.
     *
     * @param severity the threat severity
     * @return ZAP risk level
     */
    private int mapSeverityToRisk(String severity) {
        return switch (severity.toLowerCase()) {
            case "critical", "high" -> org.parosproxy.paros.core.scanner.Alert.RISK_HIGH;
            case "medium" -> org.parosproxy.paros.core.scanner.Alert.RISK_MEDIUM;
            case "low" -> org.parosproxy.paros.core.scanner.Alert.RISK_LOW;
            case "info" -> org.parosproxy.paros.core.scanner.Alert.RISK_INFO;
            default -> org.parosproxy.paros.core.scanner.Alert.RISK_LOW;
        };
    }

    /**
     * Get solution for a specific threat type.
     *
     * @param threatType the threat type
     * @return solution text
     */
    private String getSolutionForThreat(String threatType) {
        return switch (threatType.toLowerCase()) {
            case "prompt_injection" -> "Implement prompt sanitization and validation. Use structured prompts with clear boundaries. Validate user input before passing to AI models.";
            case "model_manipulation" -> "Restrict model parameter modification. Implement parameter validation and limits. Use predefined model configurations.";
            case "data_exfiltration" -> "Implement data access controls. Sanitize AI responses. Monitor for unusual data access patterns.";
            case "rate_limit_bypass" -> "Implement proper rate limiting. Use distributed rate limiting. Monitor for abuse patterns.";
            case "api_key_exposure" -> "Use secure key storage. Rotate keys regularly. Implement proper authentication mechanisms.";
            case "resource_exhaustion" -> "Implement resource limits. Monitor usage patterns. Use circuit breakers for resource protection.";
            case "suspicious_activity" -> "Implement behavioral monitoring. Set up alerts for anomalous patterns. Review access logs.";
            case "jailbreak_attempt" -> "Implement jailbreak detection. Use multiple validation layers. Monitor for bypass attempts.";
            case "adversarial_input" -> "Implement input sanitization. Use adversarial training. Validate inputs against known attack patterns.";
            default -> "Review and implement appropriate security controls for this threat type.";
        };
    }

    /**
     * Get reference information for a specific threat type.
     *
     * @param threatType the threat type
     * @return reference text
     */
    private String getReferenceForThreat(String threatType) {
        return switch (threatType.toLowerCase()) {
            case "prompt_injection" -> "OWASP AI Security: https://owasp.org/www-project-ai-security/\nOWASP Prompt Injection: https://owasp.org/www-project-ai-security/prompt-injection/";
            case "model_manipulation" -> "OWASP AI Security: https://owasp.org/www-project-ai-security/\nModel Parameter Security Best Practices";
            case "data_exfiltration" -> "OWASP Data Protection: https://owasp.org/www-project-data-protection/\nAI Data Exfiltration Prevention";
            case "rate_limit_bypass" -> "OWASP Rate Limiting Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Rate_Limiting_Cheat_Sheet.html";
            case "api_key_exposure" -> "OWASP API Security: https://owasp.org/www-project-api-security/\nAPI Key Management Best Practices";
            case "resource_exhaustion" -> "OWASP Resource Management: https://owasp.org/www-community/attacks/Resource_exhaustion_attack";
            case "suspicious_activity" -> "OWASP Logging Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html";
            case "jailbreak_attempt" -> "OWASP AI Security: https://owasp.org/www-project-ai-security/\nJailbreak Attack Prevention";
            case "adversarial_input" -> "OWASP AI Security: https://owasp.org/www-project-ai-security/\nAdversarial Input Detection";
            default -> "OWASP AI Security Project: https://owasp.org/www-project-ai-security/";
        };
    }

    public String getName() {
        return "AI Security Passive Scanner";
    }

    public int getId() {
        return 100001; // Unique scanner ID
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

        if (apiKey != null && !apiKey.trim().isEmpty()) {
            // Close existing client if any
            if (this.backendClient != null) {
                this.backendClient.close();
            }

            // Create new backend client for additional operations
            this.backendClient = new BackendClient(apiKey, backendUrl);

            // Validate API key
            if (!this.backendClient.validateApiKey()) {
                logger.warn("API key validation failed for passive scan rules, backend integration disabled");
                this.backendClient.close();
                this.backendClient = null;
                return;
            }

            logger.info("Backend integration enabled for passive scan rules");
        } else {
            // Disable backend integration
            if (this.backendClient != null) {
                this.backendClient.close();
                this.backendClient = null;
            }
            logger.info("Backend integration disabled for passive scan rules");
        }
    }
}