package net.tavoai.zap.ai.config;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.prefs.Preferences;

/**
 * Configuration manager for the AI Security Plugin.
 *
 * Handles API keys, backend settings, and customer-specific configurations.
 */
public class AIPluginConfig {

    private static final Logger logger = LogManager.getLogger(AIPluginConfig.class);

    private static final String PREF_NODE = "net/tavoai/zap/ai";

    // Configuration keys
    private static final String API_KEY = "api_key";
    private static final String BACKEND_URL = "backend_url";
    private static final String SUBMIT_SUSPICIOUS = "submit_suspicious";
    private static final String SUBMIT_BORDERLINE = "submit_borderline";
    private static final String PREMIUM_ENABLED = "premium_enabled";
    private static final String CUSTOMER_ID = "customer_id";
    private static final String DASHBOARD_ENABLED = "dashboard_enabled";

    private final Preferences prefs;

    /**
     * Constructor.
     */
    public AIPluginConfig() {
        this.prefs = Preferences.userRoot().node(PREF_NODE);
    }

    /**
     * Get the API key.
     *
     * @return the API key or null if not set
     */
    public String getApiKey() {
        return prefs.get(API_KEY, null);
    }

    /**
     * Set the API key.
     *
     * @param apiKey the API key
     */
    public void setApiKey(String apiKey) {
        if (apiKey == null || apiKey.trim().isEmpty()) {
            prefs.remove(API_KEY);
            logger.info("API key cleared");
        } else {
            prefs.put(API_KEY, apiKey.trim());
            logger.info("API key configured");
        }
    }

    /**
     * Get the backend URL.
     *
     * @return the backend URL
     */
    public String getBackendUrl() {
        return prefs.get(BACKEND_URL, "https://api.tavoai.net");
    }

    /**
     * Set the backend URL.
     *
     * @param backendUrl the backend URL
     */
    public void setBackendUrl(String backendUrl) {
        if (backendUrl == null || backendUrl.trim().isEmpty()) {
            prefs.remove(BACKEND_URL);
        } else {
            prefs.put(BACKEND_URL, backendUrl.trim());
            logger.info("Backend URL set to: {}", backendUrl);
        }
    }

    /**
     * Check if suspicious content submission is enabled.
     *
     * @return true if enabled
     */
    public boolean isSubmitSuspiciousEnabled() {
        return prefs.getBoolean(SUBMIT_SUSPICIOUS, true);
    }

    /**
     * Set suspicious content submission.
     *
     * @param enabled true to enable
     */
    public void setSubmitSuspiciousEnabled(boolean enabled) {
        prefs.putBoolean(SUBMIT_SUSPICIOUS, enabled);
        logger.info("Submit suspicious content: {}", enabled);
    }

    /**
     * Check if borderline content submission is enabled.
     *
     * @return true if enabled
     */
    public boolean isSubmitBorderlineEnabled() {
        return prefs.getBoolean(SUBMIT_BORDERLINE, false);
    }

    /**
     * Set borderline content submission.
     *
     * @param enabled true to enable
     */
    public void setSubmitBorderlineEnabled(boolean enabled) {
        prefs.putBoolean(SUBMIT_BORDERLINE, enabled);
        logger.info("Submit borderline content: {}", enabled);
    }

    /**
     * Check if premium features are enabled.
     *
     * @return true if premium features are enabled
     */
    public boolean isPremiumEnabled() {
        return prefs.getBoolean(PREMIUM_ENABLED, false);
    }

    /**
     * Set premium features enabled.
     *
     * @param enabled true to enable premium features
     */
    public void setPremiumEnabled(boolean enabled) {
        prefs.putBoolean(PREMIUM_ENABLED, enabled);
        logger.info("Premium features: {}", enabled ? "enabled" : "disabled");
    }

    /**
     * Get the customer ID.
     *
     * @return the customer ID or null if not set
     */
    public String getCustomerId() {
        return prefs.get(CUSTOMER_ID, null);
    }

    /**
     * Set the customer ID.
     *
     * @param customerId the customer ID
     */
    public void setCustomerId(String customerId) {
        if (customerId == null || customerId.trim().isEmpty()) {
            prefs.remove(CUSTOMER_ID);
        } else {
            prefs.put(CUSTOMER_ID, customerId.trim());
            logger.info("Customer ID set to: {}", customerId);
        }
    }

    /**
     * Check if dashboard integration is enabled.
     *
     * @return true if dashboard is enabled
     */
    public boolean isDashboardEnabled() {
        return prefs.getBoolean(DASHBOARD_ENABLED, false);
    }

    /**
     * Set dashboard integration enabled.
     *
     * @param enabled true to enable dashboard
     */
    public void setDashboardEnabled(boolean enabled) {
        prefs.putBoolean(DASHBOARD_ENABLED, enabled);
        logger.info("Dashboard integration: {}", enabled ? "enabled" : "disabled");
    }

    /**
     * Check if backend integration is configured and enabled.
     *
     * @return true if backend integration is ready
     */
    public boolean isBackendEnabled() {
        return getApiKey() != null && !getApiKey().trim().isEmpty();
    }

    /**
     * Clear all configuration settings.
     */
    public void clearAll() {
        try {
            prefs.clear();
            logger.info("All configuration cleared");
        } catch (Exception e) {
            logger.error("Failed to clear configuration: {}", e.getMessage());
        }
    }

    /**
     * Get configuration summary for logging/debugging.
     *
     * @return configuration summary string
     */
    public String getConfigSummary() {
        return String.format(
            "AI Plugin Config - Backend: %s, Premium: %s, Dashboard: %s, Customer: %s",
            isBackendEnabled() ? "enabled" : "disabled",
            isPremiumEnabled() ? "enabled" : "disabled",
            isDashboardEnabled() ? "enabled" : "disabled",
            getCustomerId() != null ? getCustomerId() : "none"
        );
    }
}