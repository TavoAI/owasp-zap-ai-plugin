package net.tavoai.zap.ai.detector;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import java.util.HashMap;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

/**
 * PII (Personal Identifiable Information) Filter for AI security.
 *
 * This filter detects and masks/removes sensitive information before
 * submitting content to AI services for analysis. Critical for production use.
 */
public class PIIFilter {

    private static final Logger logger = LogManager.getLogger(PIIFilter.class);

    // PII detection patterns
    private static final Pattern EMAIL_PATTERN = Pattern.compile(
        "\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b"
    );

    private static final Pattern PHONE_PATTERN = Pattern.compile(
        "\\b(\\+?1[-.\\s]?)?\\(?([0-9]{3})\\)?[-.\\s]?([0-9]{3})[-.\\s]?([0-9]{4})\\b"
    );

    private static final Pattern SSN_PATTERN = Pattern.compile(
        "\\b[0-9]{3}-[0-9]{2}-[0-9]{4}\\b"
    );

    private static final Pattern CREDIT_CARD_PATTERN = Pattern.compile(
        "\\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6(?:011|5[0-9]{2})[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\\d{3})\\d{11})\\b"
    );

    private static final Pattern IP_ADDRESS_PATTERN = Pattern.compile(
        "\\b\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\b"
    );

    private static final Pattern API_KEY_PATTERN = Pattern.compile(
        "\\b[A-Za-z0-9]{20,}\\b"  // Generic long alphanumeric strings (potential API keys)
    );

    private static final Pattern DATABASE_URL_PATTERN = Pattern.compile(
        "\\b(jdbc:|mongodb://|postgresql://|mysql://|redis://)[^\\s\"']+\\b"
    );

    private static final Pattern INTERNAL_ID_PATTERN = Pattern.compile(
        "\\binternal_id_[0-9]+\\b"
    );

    // Configuration
    private boolean enabled = true;
    private ReplacementStrategy replacementStrategy = ReplacementStrategy.MASK;
    private Map<String, PIISeverity> severityLevels = new HashMap<>();
    private List<CustomPIIPattern> customPatterns = new ArrayList<>();

    /**
     * PII severity levels.
     */
    public enum PIISeverity {
        LOW, MEDIUM, HIGH, CRITICAL
    }

    /**
     * Replacement strategies for detected PII.
     */
    public enum ReplacementStrategy {
        MASK, REMOVE, REPLACE
    }

    /**
     * Detected PII information.
     */
    public static class PIIDetection {
        private final String type;
        private final PIISeverity severity;
        private final String originalValue;
        private final int startPosition;
        private final int endPosition;

        public PIIDetection(String type, PIISeverity severity, String originalValue, int startPosition, int endPosition) {
            this.type = type;
            this.severity = severity;
            this.originalValue = originalValue;
            this.startPosition = startPosition;
            this.endPosition = endPosition;
        }

        public String getType() { return type; }
        public PIISeverity getSeverity() { return severity; }
        public String getOriginalValue() { return originalValue; }
        public int getStartPosition() { return startPosition; }
        public int getEndPosition() { return endPosition; }
    }

    /**
     * Custom PII pattern.
     */
    public static class CustomPIIPattern {
        private final String name;
        private final Pattern pattern;
        private final PIISeverity severity;

        public CustomPIIPattern(String name, String pattern, PIISeverity severity) {
            this.name = name;
            this.pattern = Pattern.compile(pattern, Pattern.CASE_INSENSITIVE);
            this.severity = severity;
        }

        public String getName() { return name; }
        public Pattern getPattern() { return pattern; }
        public PIISeverity getSeverity() { return severity; }
    }

    /**
     * Constructor with default configuration.
     */
    public PIIFilter() {
        initializeDefaultSeverityLevels();
    }

    /**
     * Initialize default severity levels.
     */
    private void initializeDefaultSeverityLevels() {
        severityLevels.put("email", PIISeverity.MEDIUM);
        severityLevels.put("phone", PIISeverity.HIGH);
        severityLevels.put("ssn", PIISeverity.CRITICAL);
        severityLevels.put("credit_card", PIISeverity.CRITICAL);
        severityLevels.put("ip_address", PIISeverity.MEDIUM);
        severityLevels.put("api_key", PIISeverity.HIGH);
        severityLevels.put("database_url", PIISeverity.CRITICAL);
        severityLevels.put("internal_id", PIISeverity.HIGH);
    }

    /**
     * Filter PII from content.
     *
     * @param content the content to filter
     * @return filtered content safe for AI service submission
     */
    public String filterPII(String content) {
        if (!enabled || content == null || content.isEmpty()) {
            return content;
        }

        String filteredContent = content;
        List<PIIDetection> detections = detectPII(content);

        // Sort detections by position (reverse order to avoid offset issues)
        detections.sort((a, b) -> Integer.compare(b.getStartPosition(), a.getStartPosition()));

        for (PIIDetection detection : detections) {
            String replacement = getReplacementForDetection(detection);
            filteredContent = filteredContent.substring(0, detection.getStartPosition()) +
                            replacement +
                            filteredContent.substring(detection.getEndPosition());
        }

        logger.debug("Filtered {} PII detections from content", detections.size());
        return filteredContent;
    }

    /**
     * Detect PII in content.
     *
     * @param content the content to analyze
     * @return list of detected PII
     */
    public List<PIIDetection> detectPII(String content) {
        List<PIIDetection> detections = new ArrayList<>();

        if (!enabled || content == null || content.isEmpty()) {
            return detections;
        }

        // Detect standard PII patterns
        detections.addAll(detectPattern(content, EMAIL_PATTERN, "email"));
        detections.addAll(detectPattern(content, PHONE_PATTERN, "phone"));
        detections.addAll(detectPattern(content, SSN_PATTERN, "ssn"));
        detections.addAll(detectPattern(content, CREDIT_CARD_PATTERN, "credit_card"));
        detections.addAll(detectPattern(content, IP_ADDRESS_PATTERN, "ip_address"));
        detections.addAll(detectPattern(content, DATABASE_URL_PATTERN, "database_url"));
        detections.addAll(detectPattern(content, INTERNAL_ID_PATTERN, "internal_id"));

        // Detect potential API keys (long alphanumeric strings)
        detections.addAll(detectPotentialApiKeys(content));

        // Detect custom patterns
        for (CustomPIIPattern customPattern : customPatterns) {
            detections.addAll(detectPattern(content, customPattern.getPattern(), customPattern.getName()));
        }

        logger.debug("Detected {} PII items in content", detections.size());
        return detections;
    }

    /**
     * Detect pattern matches in content.
     */
    private List<PIIDetection> detectPattern(String content, Pattern pattern, String type) {
        List<PIIDetection> detections = new ArrayList<>();
        Matcher matcher = pattern.matcher(content);

        while (matcher.find()) {
            PIISeverity severity = severityLevels.getOrDefault(type, PIISeverity.MEDIUM);
            String originalValue = matcher.group();

            PIIDetection detection = new PIIDetection(
                type,
                severity,
                originalValue,
                matcher.start(),
                matcher.end()
            );
            detections.add(detection);
        }

        return detections;
    }

    /**
     * Detect potential API keys (heuristic-based detection).
     */
    private List<PIIDetection> detectPotentialApiKeys(String content) {
        List<PIIDetection> detections = new ArrayList<>();
        Matcher matcher = API_KEY_PATTERN.matcher(content);

        while (matcher.find()) {
            String potentialKey = matcher.group();

            // Heuristics to identify likely API keys
            if (isLikelyApiKey(potentialKey)) {
                PIIDetection detection = new PIIDetection(
                    "api_key",
                    PIISeverity.HIGH,
                    potentialKey,
                    matcher.start(),
                    matcher.end()
                );
                detections.add(detection);
            }
        }

        return detections;
    }

    /**
     * Check if a string is likely an API key based on heuristics.
     */
    private boolean isLikelyApiKey(String str) {
        if (str.length() < 20) return false;

        // Check for mixed case, numbers, and special characters
        boolean hasUpper = str.chars().anyMatch(Character::isUpperCase);
        boolean hasLower = str.chars().anyMatch(Character::isLowerCase);
        boolean hasDigit = str.chars().anyMatch(Character::isDigit);
        boolean hasSpecial = str.chars().anyMatch(ch -> !Character.isLetterOrDigit(ch));

        // API keys typically have mixed character types
        int typeCount = (hasUpper ? 1 : 0) + (hasLower ? 1 : 0) + (hasDigit ? 1 : 0) + (hasSpecial ? 1 : 0);

        return typeCount >= 2;
    }

    /**
     * Get replacement string for a PII detection.
     */
    private String getReplacementForDetection(PIIDetection detection) {
        return switch (replacementStrategy) {
            case MASK -> maskValue(detection.getOriginalValue(), detection.getType());
            case REMOVE -> "";
            case REPLACE -> "[" + detection.getType().toUpperCase() + "_REDACTED]";
        };
    }

    /**
     * Mask a PII value based on its type.
     */
    private String maskValue(String value, String type) {
        return switch (type) {
            case "email" -> maskEmail(value);
            case "phone" -> maskPhone(value);
            case "ssn" -> maskSSN(value);
            case "credit_card" -> maskCreditCard(value);
            case "api_key" -> maskApiKey(value);
            default -> "*".repeat(Math.min(value.length(), 20));
        };
    }

    private String maskEmail(String email) {
        int atIndex = email.indexOf('@');
        if (atIndex > 0) {
            String username = email.substring(0, atIndex);
            String domain = email.substring(atIndex);
            return "*".repeat(Math.min(username.length(), 3)) + domain;
        }
        return "*".repeat(email.length());
    }

    private String maskPhone(String phone) {
        // Keep area code, mask rest
        if (phone.length() >= 10) {
            return phone.substring(0, Math.min(3, phone.length())) + "****" + phone.substring(Math.max(0, phone.length() - 4));
        }
        return "*".repeat(phone.length());
    }

    private String maskSSN(String ssn) {
        // Mask all but last 4 digits
        return "***-**-****";
    }

    private String maskCreditCard(String card) {
        // Keep first 4 and last 4 digits
        if (card.length() >= 8) {
            return card.substring(0, 4) + "*".repeat(card.length() - 8) + card.substring(card.length() - 4);
        }
        return "*".repeat(card.length());
    }

    private String maskApiKey(String key) {
        // Keep first 4 and last 4 characters
        if (key.length() >= 8) {
            return key.substring(0, 4) + "*".repeat(key.length() - 8) + key.substring(key.length() - 4);
        }
        return "*".repeat(key.length());
    }

    // Configuration methods

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
        logger.info("PII Filter {}", enabled ? "enabled" : "disabled");
    }

    public void setReplacementStrategy(ReplacementStrategy strategy) {
        this.replacementStrategy = strategy;
        logger.info("PII Filter replacement strategy set to: {}", strategy);
    }

    public void setSeverityLevel(String type, PIISeverity severity) {
        severityLevels.put(type, severity);
        logger.info("PII severity level for {} set to: {}", type, severity);
    }

    public void addCustomPattern(String name, String pattern, PIISeverity severity) {
        customPatterns.add(new CustomPIIPattern(name, pattern, severity));
        logger.info("Added custom PII pattern: {}", name);
    }

    public void removeCustomPattern(String name) {
        customPatterns.removeIf(pattern -> pattern.getName().equals(name));
        logger.info("Removed custom PII pattern: {}", name);
    }

    public boolean isEnabled() {
        return enabled;
    }

    public ReplacementStrategy getReplacementStrategy() {
        return replacementStrategy;
    }

    public Map<String, PIISeverity> getSeverityLevels() {
        return new HashMap<>(severityLevels);
    }

    public List<CustomPIIPattern> getCustomPatterns() {
        return new ArrayList<>(customPatterns);
    }
}