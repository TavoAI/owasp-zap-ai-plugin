package net.tavoai.zap.ai.model;

/**
 * Enumeration of AI security threat types.
 */
public enum ThreatType {

    /**
     * Attempts to inject malicious prompts into AI systems.
     */
    PROMPT_INJECTION("Prompt Injection"),

    /**
     * Attempts to manipulate AI model parameters or behavior.
     */
    MODEL_MANIPULATION("Model Manipulation"),

    /**
     * Attempts to extract sensitive data through AI interactions.
     */
    DATA_EXFILTRATION("Data Exfiltration"),

    /**
     * Attempts to bypass rate limiting mechanisms.
     */
    RATE_LIMIT_BYPASS("Rate Limit Bypass"),

    /**
     * Exposure of API keys or authentication tokens.
     */
    API_KEY_EXPOSURE("API Key Exposure"),

    /**
     * Attempts to exhaust AI system resources (tokens, compute, etc.).
     */
    RESOURCE_EXHAUSTION("Resource Exhaustion"),

    /**
     * Suspicious or anomalous activity patterns.
     */
    SUSPICIOUS_ACTIVITY("Suspicious Activity"),

    /**
     * Attempts to jailbreak or bypass AI safety mechanisms.
     */
    JAILBREAK_ATTEMPT("Jailbreak Attempt"),

    /**
     * Malicious input designed to confuse or manipulate AI responses.
     */
    ADVERSARIAL_INPUT("Adversarial Input");

    private final String displayName;

    ThreatType(String displayName) {
        this.displayName = displayName;
    }

    /**
     * Get the display name for this threat type.
     *
     * @return display name
     */
    public String getDisplayName() {
        return displayName;
    }

    @Override
    public String toString() {
        return displayName;
    }
}