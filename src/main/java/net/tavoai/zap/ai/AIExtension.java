package net.tavoai.zap.ai;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.zaproxy.zap.Version;

import net.tavoai.zap.ai.scan.AIScanController;
import net.tavoai.zap.ai.rules.AIActiveScanRules;
import net.tavoai.zap.ai.rules.AIPassiveScanRules;
import net.tavoai.zap.ai.api.AIApiImplementor;
import net.tavoai.zap.ai.config.AIPluginConfig;

/**
 * Main extension class for the OWASP ZAP AI Plugin.
 *
 * This extension provides AI-specific security testing capabilities
 * for web applications that interact with AI services.
 */
public class AIExtension extends ExtensionAdaptor {

    private static final Logger logger = LogManager.getLogger(AIExtension.class);

    private static final String NAME = "AI Security Testing";
    private static final String DESCRIPTION = "AI-specific security testing extension for OWASP ZAP";

    // Extension components
    private AIScanController scanController;
    private AIActiveScanRules activeScanRules;
    private AIPassiveScanRules passiveScanRules;
    private AIApiImplementor apiImplementor;
    private AIPluginConfig config;

    /**
     * Default constructor.
     */
    public AIExtension() {
        super(NAME);
        logger.info("Initializing AI Security Testing extension");
    }

    @Override
    public void init() {
        super.init();

        // Initialize configuration
        this.config = new AIPluginConfig();

        // Initialize components
        this.scanController = new AIScanController();
        this.activeScanRules = new AIActiveScanRules();
        this.passiveScanRules = new AIPassiveScanRules();
        this.apiImplementor = new AIApiImplementor();

        // Configure backend integration if API key is available
        configureBackendIntegration();

        logger.info("AI Security Testing extension initialized");
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        // Register API implementor
        extensionHook.addApiImplementor(apiImplementor);

        // Note: Active and passive scanners are registered through ZAP's plugin system
        // They will be automatically discovered when extending AbstractPlugin

        logger.info("AI Security Testing extension hooked");
    }

    @Override
    public void unload() {
        // Cleanup resources
        if (scanController != null) {
            scanController.shutdown();
        }

        logger.info("AI Security Testing extension unloaded");
        super.unload();
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public String getAuthor() {
        return "TavoAI";
    }

    @Override
    public Version getVersion() {
        return new Version("1.0.0");
    }

    /**
     * Configure backend integration based on stored configuration.
     */
    private void configureBackendIntegration() {
        try {
            String apiKey = config.getApiKey();
            String backendUrl = config.getBackendUrl();
            boolean submitSuspicious = config.isSubmitSuspiciousEnabled();
            boolean submitBorderline = config.isSubmitBorderlineEnabled();

            if (apiKey != null && !apiKey.trim().isEmpty()) {
                // Configure the detector with backend settings
                if (scanController != null && scanController.getDetector() != null) {
                    scanController.getDetector().configureBackend(apiKey, backendUrl, submitSuspicious, submitBorderline);
                    logger.info("Backend integration configured for detector");
                }

                // Configure active scan rules
                if (activeScanRules != null) {
                    activeScanRules.configureBackend(apiKey, backendUrl, submitSuspicious, submitBorderline);
                }

                // Configure passive scan rules
                if (passiveScanRules != null) {
                    passiveScanRules.configureBackend(apiKey, backendUrl, submitSuspicious, submitBorderline);
                }
            } else {
                logger.info("No API key configured, running in standalone mode");
            }
        } catch (Exception e) {
            logger.error("Failed to configure backend integration: {}", e.getMessage(), e);
        }
    }

    /**
     * Get the plugin configuration.
     *
     * @return the AI plugin configuration
     */
    public AIPluginConfig getConfig() {
        return config;
    }

    /**
     * Get the active scan rules.
     *
     * @return the AI active scan rules
     */
    public AIActiveScanRules getActiveScanRules() {
        return activeScanRules;
    }

    /**
     * Get the passive scan rules.
     *
     * @return the AI passive scan rules
     */
    public AIPassiveScanRules getPassiveScanRules() {
        return passiveScanRules;
    }
}