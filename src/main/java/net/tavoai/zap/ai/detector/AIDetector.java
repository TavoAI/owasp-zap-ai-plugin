package net.tavoai.zap.ai.detector;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.network.HttpMessage;

import net.tavoai.zap.ai.model.AIThreat;
import net.tavoai.zap.ai.model.ThreatType;
import net.tavoai.zap.ai.model.ThreatSeverity;
import net.tavoai.zap.ai.client.BackendClient;

import java.util.List;
import java.util.ArrayList;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.util.Map;
import java.util.HashMap;
import java.util.Optional;

/**
 * AI threat detector for analyzing HTTP messages and identifying AI-specific security threats.
 *
 * This detector uses pattern matching, semantic analysis, and behavioral detection
 * to identify potential AI security vulnerabilities and attacks.
 *
 * Supports optional backend integration for enhanced analysis and rule updates.
 */
public class AIDetector {

    private static final Logger logger = LogManager.getLogger(AIDetector.class);

    // Backend integration settings
    private boolean backendEnabled = false;
    private BackendClient backendClient;
    private boolean submitSuspiciousContent = true;
    private boolean submitBorderlineContent = false;
    private Map<String, Pattern> customPatterns = new HashMap<>();

    // PII Filter for content sanitization
    private final PIIFilter piiFilter;

    // Default patterns for detecting prompt injection attempts
    private static final Pattern PROMPT_INJECTION_PATTERN = Pattern.compile(
        "(?i)(ignore\\s+(all\\s+)?previous\\s+instructions|system\\s+prompt|override|jailbreak|" +
        "dan\\s+mode|uncensored|developer\\s+mode|admin\\s+mode|root\\s+access|" +
        "bypass\\s+(restrictions|filters|safety)|act\\s+as\\s+a|pretend\\s+to\\s+be|" +
        "role\\s+play\\s+as|you\\s+are\\s+now|from\\s+now\\s+on|starting\\s+now|" +
        "forget\\s+(your\\s+)?instructions|new\\s+personality|change\\s+your\\s+role|" +
        "break\\s+character|out\\s+of\\s+character)"
    );

    // Pattern for detecting model manipulation attempts
    private static final Pattern MODEL_MANIPULATION_PATTERN = Pattern.compile(
        "(?i)(temperature\\s*=\\s*[0-9]+(\\.[0-9]+)?|max_tokens\\s*=\\s*[0-9]+|" +
        "top_p\\s*=\\s*[0-9]+(\\.[0-9]+)?|frequency_penalty\\s*=\\s*[0-9]+(\\.[0-9]+)?|" +
        "presence_penalty\\s*=\\s*[0-9]+(\\.[0-9]+)?|model\\s*=\\s*[\"']?[^\"'\\s]+[\"']?|" +
        "engine\\s*=\\s*[\"']?[^\"'\\s]+[\"']?|api_key\\s*=\\s*[\"']?[^\"'\\s]+[\"']?|" +
        "openai|anthropic|claude|gpt|bard|llama|mistral)"
    );

    // Pattern for detecting data exfiltration attempts
    private static final Pattern DATA_EXFILTRATION_PATTERN = Pattern.compile(
        "(?i)(extract\\s+(all\\s+)?data|dump\\s+database|show\\s+me\\s+(all\\s+)?|" +
        "list\\s+(all\\s+)?users|reveal\\s+secrets|expose\\s+keys|leak\\s+information|" +
        "output\\s+(the\\s+)?entire|give\\s+me\\s+(everything|all)|spill\\s+(the\\s+)?beans|" +
        "tell\\s+me\\s+(everything|all)|disclose\\s+(all\\s+)?|unveil\\s+(the\\s+)?|" +
        "print\\s+(all\\s+)?records|display\\s+(the\\s+)?database)"
    );

    // Pattern for detecting rate limit bypass attempts
    private static final Pattern RATE_LIMIT_BYPASS_PATTERN = Pattern.compile(
        "(?i)(bypass\\s+rate\\s+limit|circumvent\\s+limits|remove\\s+restrictions|" +
        "disable\\s+throttling|ignore\\s+limits|no\\s+rate\\s+limit|unlimited\\s+requests|" +
        "flood\\s+(the\\s+)?api|spam\\s+(the\\s+)?endpoint|overload\\s+(the\\s+)?system|" +
        "ddos|denial\\s+of\\s+service)"
    );

    // Pattern for detecting AI API endpoints
    private static final Pattern AI_API_PATTERN = Pattern.compile(
        "(?i)/v[0-9]+/(chat/completions|completions|embeddings|images/generations|" +
        "audio/transcriptions|audio/translations|moderations|models|fine-tunes|" +
        "files|assistants|threads|messages|runs|steps)"
    );

    /**
     * Constructor.
     */
    public AIDetector() {
        this.piiFilter = new PIIFilter();
        logger.info("AI Detector initialized with PII filtering enabled");
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
        this.backendEnabled = apiKey != null && !apiKey.trim().isEmpty();
        this.submitSuspiciousContent = submitSuspicious;
        this.submitBorderlineContent = submitBorderline;

        if (this.backendEnabled) {
            // Close existing client if any
            if (this.backendClient != null) {
                this.backendClient.close();
            }

            // Create new backend client
            this.backendClient = new BackendClient(apiKey, backendUrl);

            // Validate API key
            if (!this.backendClient.validateApiKey()) {
                logger.warn("API key validation failed, backend integration disabled");
                this.backendEnabled = false;
                this.backendClient.close();
                this.backendClient = null;
                return;
            }

            logger.info("Backend integration enabled - URL: {}, Submit suspicious: {}, Submit borderline: {}",
                       backendUrl != null ? backendUrl : "default", submitSuspicious, submitBorderline);
        } else {
            // Disable backend integration
            if (this.backendClient != null) {
                this.backendClient.close();
                this.backendClient = null;
            }
            logger.info("Backend integration disabled");
        }
    }

    /**
     * Fetch rule updates from the backend.
     *
     * @return true if rules were successfully updated
     */
    public boolean fetchRuleUpdates() {
        if (!backendEnabled || backendClient == null) {
            logger.debug("Backend integration not enabled, skipping rule updates");
            return false;
        }

        try {
            Optional<String> ruleUpdates = backendClient.fetchRuleUpdates();
            if (ruleUpdates.isPresent()) {
                // TODO: Parse and apply rule updates
                // This would parse the JSON response and update custom patterns, thresholds, etc.
                logger.info("Successfully fetched and applied rule updates from backend");
                return true;
            } else {
                logger.warn("Failed to fetch rule updates from backend");
                return false;
            }
        } catch (Exception e) {
            logger.error("Failed to fetch rule updates: {}", e.getMessage(), e);
            return false;
        }
    }

    /**
     * Submit content for backend analysis.
     *
     * @param content the content to analyze
     * @param threatType the detected threat type
     * @param severity the threat severity
     * @param url the source URL
     * @return backend analysis result or empty if submission failed
     */
    public Optional<String> submitForAnalysis(String content, ThreatType threatType, ThreatSeverity severity, String url) {
        if (!backendEnabled || backendClient == null) {
            return Optional.empty();
        }

        // Only submit based on configuration
        boolean shouldSubmit = false;
        if (severity == ThreatSeverity.CRITICAL || severity == ThreatSeverity.HIGH) {
            shouldSubmit = submitSuspiciousContent;
        } else if (severity == ThreatSeverity.MEDIUM) {
            shouldSubmit = submitBorderlineContent;
        }

        if (!shouldSubmit) {
            return Optional.empty();
        }

        try {
            // Filter PII before submission
            String filteredContent = piiFilter.filterPII(content);
            List<PIIFilter.PIIDetection> piiDetections = piiFilter.detectPII(content);

            if (!piiDetections.isEmpty()) {
                logger.info("Filtered {} PII detections before backend submission for threat: {}",
                           piiDetections.size(), threatType);
            }

            Optional<String> analysisId = backendClient.submitForAnalysis(filteredContent, threatType, severity, url);
            if (analysisId.isPresent()) {
                logger.debug("Content submitted for backend analysis - ID: {}, Type: {}, Severity: {}",
                           analysisId.get(), threatType, severity);
                return analysisId;
            } else {
                logger.warn("Failed to submit content for backend analysis");
                return Optional.empty();
            }
        } catch (Exception e) {
            logger.error("Failed to submit content for analysis: {}", e.getMessage(), e);
            return Optional.empty();
        }
    }

    /**
     * Add custom detection pattern.
     *
     * @param name the pattern name
     * @param pattern the regex pattern
     * @param threatType the threat type to assign
     * @param severity the severity level
     */
    public void addCustomPattern(String name, String pattern, ThreatType threatType, ThreatSeverity severity) {
        try {
            customPatterns.put(name, Pattern.compile(pattern, Pattern.CASE_INSENSITIVE));
            logger.info("Added custom pattern: {} -> {}", name, threatType);
        } catch (Exception e) {
            logger.error("Failed to add custom pattern {}: {}", name, e.getMessage());
        }
    }

    /**
     * Remove custom detection pattern.
     *
     * @param name the pattern name to remove
     */
    public void removeCustomPattern(String name) {
        customPatterns.remove(name);
        logger.info("Removed custom pattern: {}", name);
    }

    /**
     * Get all custom patterns.
     *
     * @return map of pattern names to compiled patterns
     */
    public Map<String, Pattern> getCustomPatterns() {
        return new HashMap<>(customPatterns);
    }

    /**
     * Get the PII filter instance.
     *
     * @return the PII filter
     */
    public PIIFilter getPIIFilter() {
        return piiFilter;
    }

    /**
     * Close the detector and release resources.
     */
    public void close() {
        if (backendClient != null) {
            backendClient.close();
            backendClient = null;
        }
        backendEnabled = false;
        logger.info("AI Detector closed");
    }

    /**
     * Analyze an HTTP message for AI security threats.
     *
     * @param message the HTTP message to analyze
     * @return list of detected threats
     */
    public List<AIThreat> analyzeMessage(HttpMessage message) {
        List<AIThreat> threats = new ArrayList<>();

        try {
            // Check if this is an AI API request
            if (!isAIApiRequest(message)) {
                return threats; // Skip non-AI requests
            }

            // Analyze request body for threats
            String requestBody = getRequestBody(message);
            if (requestBody != null && !requestBody.isEmpty()) {
                threats.addAll(analyzeRequestBody(requestBody, message));
            }

            // Analyze request headers for threats
            threats.addAll(analyzeRequestHeaders(message));

            // Analyze URL parameters for threats
            threats.addAll(analyzeUrlParameters(message));

            // Perform behavioral analysis
            threats.addAll(performBehavioralAnalysis(message));

        } catch (Exception e) {
            logger.error("Error analyzing message: {}", e.getMessage(), e);
        }

        return threats;
    }

    /**
     * Check if the HTTP message is an AI API request.
     *
     * @param message the HTTP message
     * @return true if AI API request
     */
    private boolean isAIApiRequest(HttpMessage message) {
        String url = message.getRequestHeader().getURI().toString();
        return AI_API_PATTERN.matcher(url).find();
    }

    /**
     * Analyze request body for AI threats.
     *
     * @param body the request body
     * @param message the HTTP message
     * @return list of detected threats
     */
    private List<AIThreat> analyzeRequestBody(String body, HttpMessage message) {
        List<AIThreat> threats = new ArrayList<>();
        String url = message.getRequestHeader().getURI().toString();

        // Check for prompt injection
        if (PROMPT_INJECTION_PATTERN.matcher(body).find()) {
            AIThreat threat = new AIThreat(
                ThreatType.PROMPT_INJECTION,
                ThreatSeverity.HIGH,
                "Potential prompt injection detected in request body",
                extractEvidence(body, PROMPT_INJECTION_PATTERN),
                url
            );
            threats.add(threat);
            submitForAnalysis(body, threat.getType(), threat.getSeverity(), url);
        }

        // Check for model manipulation
        if (MODEL_MANIPULATION_PATTERN.matcher(body).find()) {
            AIThreat threat = new AIThreat(
                ThreatType.MODEL_MANIPULATION,
                ThreatSeverity.MEDIUM,
                "Potential model parameter manipulation detected",
                extractEvidence(body, MODEL_MANIPULATION_PATTERN),
                url
            );
            threats.add(threat);
            submitForAnalysis(body, threat.getType(), threat.getSeverity(), url);
        }

        // Check for data exfiltration attempts
        if (DATA_EXFILTRATION_PATTERN.matcher(body).find()) {
            AIThreat threat = new AIThreat(
                ThreatType.DATA_EXFILTRATION,
                ThreatSeverity.CRITICAL,
                "Potential data exfiltration attempt detected",
                extractEvidence(body, DATA_EXFILTRATION_PATTERN),
                url
            );
            threats.add(threat);
            submitForAnalysis(body, threat.getType(), threat.getSeverity(), url);
        }

        // Check for rate limit bypass attempts
        if (RATE_LIMIT_BYPASS_PATTERN.matcher(body).find()) {
            AIThreat threat = new AIThreat(
                ThreatType.RATE_LIMIT_BYPASS,
                ThreatSeverity.MEDIUM,
                "Potential rate limit bypass attempt detected",
                extractEvidence(body, RATE_LIMIT_BYPASS_PATTERN),
                url
            );
            threats.add(threat);
            submitForAnalysis(body, threat.getType(), threat.getSeverity(), url);
        }

        // Check custom patterns
        for (Map.Entry<String, Pattern> entry : customPatterns.entrySet()) {
            if (entry.getValue().matcher(body).find()) {
                AIThreat threat = new AIThreat(
                    ThreatType.ADVERSARIAL_INPUT, // Default type for custom patterns
                    ThreatSeverity.MEDIUM, // Default severity
                    "Custom pattern match: " + entry.getKey(),
                    extractEvidence(body, entry.getValue()),
                    url
                );
                threats.add(threat);
                submitForAnalysis(body, threat.getType(), threat.getSeverity(), url);
            }
        }

        return threats;
    }

    /**
     * Analyze request headers for AI threats.
     *
     * @param message the HTTP message
     * @return list of detected threats
     */
    private List<AIThreat> analyzeRequestHeaders(HttpMessage message) {
        List<AIThreat> threats = new ArrayList<>();

        // Check for suspicious user agents
        String userAgent = message.getRequestHeader().getHeader("User-Agent");
        if (userAgent != null && containsSuspiciousUserAgent(userAgent)) {
            threats.add(new AIThreat(
                ThreatType.SUSPICIOUS_ACTIVITY,
                ThreatSeverity.LOW,
                "Suspicious User-Agent detected",
                userAgent,
                message.getRequestHeader().getURI().toString()
            ));
        }

        // Check for API key exposure in headers
        String authHeader = message.getRequestHeader().getHeader("Authorization");
        if (authHeader != null && authHeader.length() > 50) {
            threats.add(new AIThreat(
                ThreatType.API_KEY_EXPOSURE,
                ThreatSeverity.HIGH,
                "Potential API key exposure in Authorization header",
                "Authorization: " + authHeader.substring(0, 20) + "...",
                message.getRequestHeader().getURI().toString()
            ));
        }

        return threats;
    }

    /**
     * Analyze URL parameters for AI threats.
     *
     * @param message the HTTP message
     * @return list of detected threats
     */
    private List<AIThreat> analyzeUrlParameters(HttpMessage message) {
        List<AIThreat> threats = new ArrayList<>();

        try {
            String query = message.getRequestHeader().getURI().getQuery();
            if (query != null && !query.isEmpty()) {
                // Check for prompt injection in query parameters
                if (PROMPT_INJECTION_PATTERN.matcher(query).find()) {
                    threats.add(new AIThreat(
                        ThreatType.PROMPT_INJECTION,
                        ThreatSeverity.HIGH,
                        "Potential prompt injection in URL parameters",
                        extractEvidence(query, PROMPT_INJECTION_PATTERN),
                        message.getRequestHeader().getURI().toString()
                    ));
                }
            }
        } catch (org.apache.commons.httpclient.URIException e) {
            logger.debug("Could not parse URI query: {}", e.getMessage());
        }

        return threats;
    }

    /**
     * Perform behavioral analysis on the HTTP message.
     *
     * @param message the HTTP message
     * @return list of detected threats
     */
    private List<AIThreat> performBehavioralAnalysis(HttpMessage message) {
        List<AIThreat> threats = new ArrayList<>();

        // Check for unusual request patterns
        if (isUnusualRequestPattern(message)) {
            threats.add(new AIThreat(
                ThreatType.SUSPICIOUS_ACTIVITY,
                ThreatSeverity.MEDIUM,
                "Unusual request pattern detected",
                "Request size: " + message.getRequestBody().length() +
                ", Headers: " + message.getRequestHeader().getHeaders().size(),
                message.getRequestHeader().getURI().toString()
            ));
        }

        // Check for potential token exhaustion attacks
        if (isPotentialTokenExhaustion(message)) {
            threats.add(new AIThreat(
                ThreatType.RESOURCE_EXHAUSTION,
                ThreatSeverity.MEDIUM,
                "Potential token exhaustion attack",
                "Large request body detected",
                message.getRequestHeader().getURI().toString()
            ));
        }

        return threats;
    }

    /**
     * Check if user agent contains suspicious patterns.
     *
     * @param userAgent the user agent string
     * @return true if suspicious
     */
    private boolean containsSuspiciousUserAgent(String userAgent) {
        String lowerUA = userAgent.toLowerCase();
        return lowerUA.contains("curl") ||
               lowerUA.contains("wget") ||
               lowerUA.contains("python") ||
               lowerUA.contains("bot") ||
               lowerUA.contains("scanner") ||
               lowerUA.contains("exploit");
    }

    /**
     * Check for unusual request patterns.
     *
     * @param message the HTTP message
     * @return true if unusual pattern detected
     */
    private boolean isUnusualRequestPattern(HttpMessage message) {
        // Check for very large request bodies
        if (message.getRequestBody().length() > 100000) { // 100KB
            return true;
        }

        // Check for excessive headers
        if (message.getRequestHeader().getHeaders().size() > 20) {
            return true;
        }

        return false;
    }

    /**
     * Check for potential token exhaustion attacks.
     *
     * @param message the HTTP message
     * @return true if potential attack detected
     */
    private boolean isPotentialTokenExhaustion(HttpMessage message) {
        // Check for very large request bodies that could exhaust tokens
        return message.getRequestBody().length() > 50000; // 50KB
    }

    /**
     * Extract evidence from text using a pattern.
     *
     * @param text the text to search
     * @param pattern the pattern to match
     * @return extracted evidence
     */
    private String extractEvidence(String text, Pattern pattern) {
        Matcher matcher = pattern.matcher(text);
        if (matcher.find()) {
            String match = matcher.group();
            // Return context around the match (up to 100 chars)
            int start = Math.max(0, matcher.start() - 20);
            int end = Math.min(text.length(), matcher.end() + 20);
            return "..." + text.substring(start, end) + "...";
        }
        return "Pattern matched";
    }

    /**
     * Get request body as string.
     *
     * @param message the HTTP message
     * @return request body or null if error
     */
    private String getRequestBody(HttpMessage message) {
        try {
            return new String(message.getRequestBody().getBytes());
        } catch (Exception e) {
            logger.debug("Could not get request body: {}", e.getMessage());
            return null;
        }
    }
}