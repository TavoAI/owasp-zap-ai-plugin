package net.tavoai.zap.ai.service;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import net.tavoai.zap.ai.client.BackendClient;
import net.tavoai.zap.ai.detector.AIDetector;
import net.tavoai.zap.ai.config.AIPluginConfig;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.Map;
import java.util.HashMap;
import java.util.Optional;
import java.util.List;
import java.util.ArrayList;
import java.io.*;
import java.nio.file.*;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * Backend Analysis Service for managing periodic backend operations.
 *
 * This service handles:
 * - Periodic fetching of rule updates from the backend
 * - Applying rule updates to the AI detector
 * - Managing analysis result retrieval
 * - Background processing of submitted analyses
 * - Persistent storage of analysis state and rules
 */
public class BackendAnalysisService {

    private static final Logger logger = LogManager.getLogger(BackendAnalysisService.class);

    // Service configuration
    private static final long RULE_UPDATE_INTERVAL_MINUTES = 60; // Check for updates every hour
    private static final long ANALYSIS_CHECK_INTERVAL_SECONDS = 30; // Check analysis results every 30 seconds
    private static final int MAX_CONCURRENT_ANALYSES = 10;

    // Storage configuration
    private static final String PENDING_ANALYSES_FILE = "pending-analyses.dat";
    private static final String COMPLETED_ANALYSES_FILE = "completed-analyses.dat";
    private static final String RULE_CACHE_FILE = "rule-cache.dat";

    // Service components
    private final ScheduledExecutorService scheduler;
    private final AIPluginConfig config;
    private final AIDetector aiDetector;
    private BackendClient backendClient;
    private final Path storageDir;
    private final ReadWriteLock storageLock = new ReentrantReadWriteLock();

    // Service state
    private final AtomicBoolean running = new AtomicBoolean(false);
    private final Map<String, Long> pendingAnalyses = new HashMap<>();
    private final List<String> completedAnalyses = new ArrayList<>();
    private String lastRuleUpdateHash = null;

    /**
     * Constructor.
     *
     * @param config the plugin configuration
     * @param aiDetector the AI detector instance
     */
    public BackendAnalysisService(AIPluginConfig config, AIDetector aiDetector) {
        this.config = config;
        this.aiDetector = aiDetector;
        this.scheduler = Executors.newScheduledThreadPool(2);

        // Initialize storage directory
        this.storageDir = getStorageDirectory();
        createStorageDirectory();

        // Load persistent data
        loadPersistentData();

        logger.info("Backend Analysis Service initialized with persistent storage at: {}", storageDir);
    }

    /**
     * Start the backend analysis service.
     */
    public void start() {
        if (running.getAndSet(true)) {
            logger.warn("Backend Analysis Service is already running");
            return;
        }

        if (!config.isBackendEnabled()) {
            logger.info("Backend integration not enabled, service will remain idle");
            return;
        }

        // Initialize backend client
        initializeBackendClient();

        // Schedule periodic tasks
        scheduleRuleUpdates();
        scheduleAnalysisChecks();

        logger.info("Backend Analysis Service started successfully");
    }

    /**
     * Stop the backend analysis service.
     */
    public void stop() {
        if (!running.getAndSet(false)) {
            logger.warn("Backend Analysis Service is not running");
            return;
        }

        // Save persistent data before shutdown
        savePersistentData();

        // Shutdown scheduler
        scheduler.shutdown();
        try {
            if (!scheduler.awaitTermination(30, TimeUnit.SECONDS)) {
                scheduler.shutdownNow();
                logger.warn("Backend Analysis Service shutdown forced");
            }
        } catch (InterruptedException e) {
            scheduler.shutdownNow();
            Thread.currentThread().interrupt();
        }

        // Close backend client
        if (backendClient != null) {
            backendClient.close();
            backendClient = null;
        }

        // Clear pending analyses
        pendingAnalyses.clear();
        completedAnalyses.clear();

        logger.info("Backend Analysis Service stopped");
    }

    /**
     * Check if the service is running.
     *
     * @return true if running
     */
    public boolean isRunning() {
        return running.get();
    }

    /**
     * Get the number of pending analyses.
     *
     * @return number of pending analyses
     */
    public int getPendingAnalysisCount() {
        return pendingAnalyses.size();
    }

    /**
     * Get the number of completed analyses.
     *
     * @return number of completed analyses
     */
    public int getCompletedAnalysisCount() {
        return completedAnalyses.size();
    }

    /**
     * Force immediate rule update check.
     *
     * @return true if update was successful
     */
    public boolean forceRuleUpdate() {
        if (!running.get() || backendClient == null) {
            return false;
        }

        return performRuleUpdate();
    }

    /**
     * Force immediate analysis results check.
     *
     * @return number of analyses processed
     */
    public int forceAnalysisCheck() {
        if (!running.get() || backendClient == null) {
            return 0;
        }

        return performAnalysisCheck();
    }

    /**
     * Initialize the backend client.
     */
    private void initializeBackendClient() {
        try {
            String apiKey = config.getApiKey();
            String backendUrl = config.getBackendUrl();

            if (apiKey == null || apiKey.trim().isEmpty()) {
                logger.warn("No API key configured, cannot initialize backend client");
                return;
            }

            backendClient = new BackendClient(apiKey, backendUrl);

            // Validate API key
            if (!backendClient.validateApiKey()) {
                logger.error("API key validation failed, backend client not initialized");
                backendClient.close();
                backendClient = null;
                return;
            }

            // Fetch customer configuration
            Optional<String> customerConfig = backendClient.getCustomerConfig();
            if (customerConfig.isPresent()) {
                logger.info("Retrieved customer configuration from backend");
                // TODO: Apply customer-specific configuration
            }

            logger.info("Backend client initialized successfully");

        } catch (Exception e) {
            logger.error("Failed to initialize backend client: {}", e.getMessage(), e);
            backendClient = null;
        }
    }

    /**
     * Schedule periodic rule updates.
     */
    private void scheduleRuleUpdates() {
        scheduler.scheduleAtFixedRate(
            this::performRuleUpdate,
            5, // Initial delay: 5 minutes
            RULE_UPDATE_INTERVAL_MINUTES,
            TimeUnit.MINUTES
        );

        logger.debug("Rule update scheduler configured - interval: {} minutes", RULE_UPDATE_INTERVAL_MINUTES);
    }

    /**
     * Schedule periodic analysis result checks.
     */
    private void scheduleAnalysisChecks() {
        scheduler.scheduleAtFixedRate(
            this::performAnalysisCheck,
            60, // Initial delay: 1 minute
            ANALYSIS_CHECK_INTERVAL_SECONDS,
            TimeUnit.SECONDS
        );

        logger.debug("Analysis check scheduler configured - interval: {} seconds", ANALYSIS_CHECK_INTERVAL_SECONDS);
    }

    /**
     * Perform rule update from backend.
     *
     * @return true if update was successful
     */
    private boolean performRuleUpdate() {
        if (backendClient == null) {
            logger.debug("Backend client not available, skipping rule update");
            return false;
        }

        try {
            logger.debug("Checking for rule updates from backend");

            Optional<String> ruleUpdates = backendClient.fetchRuleUpdates();
            if (ruleUpdates.isPresent()) {
                String rulesJson = ruleUpdates.get();

                // Check if rules have actually changed
                String newHash = Integer.toString(rulesJson.hashCode());
                if (newHash.equals(lastRuleUpdateHash)) {
                    logger.debug("Rules unchanged (hash: {}), skipping update", newHash);
                    return true;
                }

                // Parse and apply rule updates
                boolean applied = applyRuleUpdates(rulesJson);
                if (applied) {
                    updateRuleCache(newHash);
                    logger.info("Successfully applied rule updates from backend (hash: {})", newHash);
                    return true;
                } else {
                    logger.warn("Failed to apply rule updates from backend");
                    return false;
                }
            } else {
                logger.debug("No rule updates available from backend");
                return true; // Not an error, just no updates
            }

        } catch (Exception e) {
            logger.error("Error during rule update: {}", e.getMessage(), e);
            return false;
        }
    }

    /**
     * Perform analysis result checks.
     *
     * @return number of analyses processed
     */
    private int performAnalysisCheck() {
        if (backendClient == null || pendingAnalyses.isEmpty()) {
            return 0;
        }

        int processed = 0;
        List<String> toRemove = new ArrayList<>();

        try {
            logger.debug("Checking {} pending analyses", pendingAnalyses.size());

            for (Map.Entry<String, Long> entry : pendingAnalyses.entrySet()) {
                String analysisId = entry.getKey();
                long submissionTime = entry.getValue();

                // Check if analysis is too old (24 hours)
                long ageHours = (System.currentTimeMillis() - submissionTime) / (1000 * 60 * 60);
                if (ageHours > 24) {
                    logger.warn("Analysis {} is too old ({} hours), removing from pending", analysisId, ageHours);
                    toRemove.add(analysisId);
                    continue;
                }

                try {
                    Optional<String> results = backendClient.getAnalysisResults(analysisId);
                    if (results.isPresent()) {
                        String resultData = results.get();

                        if ("analysis_pending".equals(resultData)) {
                            // Still processing, keep in pending
                            continue;
                        }

                        // Analysis completed
                        processAnalysisResults(analysisId, resultData);
                        toRemove.add(analysisId);
                        processed++;

                        // Limit concurrent processing
                        if (processed >= MAX_CONCURRENT_ANALYSES) {
                            break;
                        }
                    } else {
                        // Analysis failed or not found
                        logger.warn("Analysis {} failed or not found, removing from pending", analysisId);
                        toRemove.add(analysisId);
                    }

                } catch (Exception e) {
                    logger.error("Error checking analysis {}: {}", analysisId, e.getMessage());
                    // Keep in pending for retry
                }
            }

            // Remove completed/failed analyses
            for (String analysisId : toRemove) {
                pendingAnalyses.remove(analysisId);
            }

        } catch (Exception e) {
            logger.error("Error during analysis check: {}", e.getMessage(), e);
        }

        if (processed > 0) {
            logger.info("Processed {} analysis results", processed);
            // Save updated state to disk
            savePersistentData();
        }

        return processed;
    }

    /**
     * Apply rule updates from backend.
     *
     * @param rulesJson the rule updates JSON
     * @return true if applied successfully
     */
    private boolean applyRuleUpdates(String rulesJson) {
        try {
            // TODO: Parse JSON and apply updates
            // This would parse the JSON structure and update:
            // - Custom patterns in AIDetector
            // - Thresholds and configuration
            // - New threat signatures

            // For now, just log the update
            logger.info("Rule updates received: {}", rulesJson.substring(0, Math.min(rulesJson.length(), 200)));

            // Placeholder: Apply some example updates
            // aiDetector.addCustomPattern("backend_rule_1", "example.*pattern", ThreatType.ADVERSARIAL_INPUT, ThreatSeverity.MEDIUM);

            return true;

        } catch (Exception e) {
            logger.error("Failed to apply rule updates: {}", e.getMessage(), e);
            return false;
        }
    }

    /**
     * Process completed analysis results.
     *
     * @param analysisId the analysis ID
     * @param resultsJson the results JSON
     */
    private void processAnalysisResults(String analysisId, String resultsJson) {
        try {
            logger.info("Processing analysis results for ID: {}", analysisId);

            // TODO: Parse results and apply insights
            // This could include:
            // - Updating threat scores
            // - Adding new patterns
            // - Adjusting detection thresholds
            // - Generating alerts

            // Add to completed list
            completedAnalyses.add(analysisId);

            // Keep only last 100 completed analyses
            if (completedAnalyses.size() > 100) {
                completedAnalyses.remove(0);
            }

            logger.debug("Analysis {} results processed successfully", analysisId);

        } catch (Exception e) {
            logger.error("Failed to process analysis results for {}: {}", analysisId, e.getMessage(), e);
        }
    }

    /**
     * Add a pending analysis for tracking.
     *
     * @param analysisId the analysis ID
     */
    public void addPendingAnalysis(String analysisId) {
        if (analysisId != null && !analysisId.trim().isEmpty()) {
            pendingAnalyses.put(analysisId, System.currentTimeMillis());
            logger.debug("Added pending analysis: {}", analysisId);
        }
    }

    /**
     * Get service status information.
     *
     * @return status information
     */
    public String getStatus() {
        return String.format(
            "BackendAnalysisService[running=%s, backendEnabled=%s, pendingAnalyses=%d, completedAnalyses=%d, storageDir=%s]",
            running.get(),
            backendClient != null,
            pendingAnalyses.size(),
            completedAnalyses.size(),
            storageDir
        );
    }

    /**
     * Get the storage directory path.
     *
     * @return path to the storage directory
     */
    private Path getStorageDirectory() {
        // Use ZAP's home directory for plugin data
        String zapHome = System.getProperty("user.home") + File.separator + ".ZAP";
        return Paths.get(zapHome, "plugin-data", "ai-plugin");
    }

    /**
     * Create the storage directory if it doesn't exist.
     */
    private void createStorageDirectory() {
        try {
            Files.createDirectories(storageDir);
            logger.debug("Created storage directory: {}", storageDir);
        } catch (IOException e) {
            logger.error("Failed to create storage directory: {}", e.getMessage(), e);
        }
    }

    /**
     * Load persistent data from disk.
     */
    private void loadPersistentData() {
        storageLock.writeLock().lock();
        try {
            loadPendingAnalyses();
            loadCompletedAnalyses();
            loadRuleCache();
            logger.info("Loaded persistent data: {} pending, {} completed analyses",
                       pendingAnalyses.size(), completedAnalyses.size());
        } finally {
            storageLock.writeLock().unlock();
        }
    }

    /**
     * Save persistent data to disk.
     */
    private void savePersistentData() {
        storageLock.writeLock().lock();
        try {
            savePendingAnalyses();
            saveCompletedAnalyses();
            saveRuleCache();
            logger.debug("Saved persistent data to disk");
        } finally {
            storageLock.writeLock().unlock();
        }
    }

    /**
     * Load pending analyses from disk.
     */
    private void loadPendingAnalyses() {
        Path file = storageDir.resolve(PENDING_ANALYSES_FILE);
        if (!Files.exists(file)) {
            return;
        }

        try (ObjectInputStream ois = new ObjectInputStream(Files.newInputStream(file))) {
            @SuppressWarnings("unchecked")
            Map<String, Long> loaded = (Map<String, Long>) ois.readObject();
            pendingAnalyses.putAll(loaded);
            logger.debug("Loaded {} pending analyses from disk", loaded.size());
        } catch (Exception e) {
            logger.warn("Failed to load pending analyses: {}", e.getMessage());
        }
    }

    /**
     * Save pending analyses to disk.
     */
    private void savePendingAnalyses() {
        Path file = storageDir.resolve(PENDING_ANALYSES_FILE);
        try (ObjectOutputStream oos = new ObjectOutputStream(Files.newOutputStream(file))) {
            oos.writeObject(new HashMap<>(pendingAnalyses));
        } catch (Exception e) {
            logger.error("Failed to save pending analyses: {}", e.getMessage(), e);
        }
    }

    /**
     * Load completed analyses from disk.
     */
    private void loadCompletedAnalyses() {
        Path file = storageDir.resolve(COMPLETED_ANALYSES_FILE);
        if (!Files.exists(file)) {
            return;
        }

        try (ObjectInputStream ois = new ObjectInputStream(Files.newInputStream(file))) {
            @SuppressWarnings("unchecked")
            List<String> loaded = (List<String>) ois.readObject();
            completedAnalyses.addAll(loaded);
            logger.debug("Loaded {} completed analyses from disk", loaded.size());
        } catch (Exception e) {
            logger.warn("Failed to load completed analyses: {}", e.getMessage());
        }
    }

    /**
     * Save completed analyses to disk.
     */
    private void saveCompletedAnalyses() {
        Path file = storageDir.resolve(COMPLETED_ANALYSES_FILE);
        try (ObjectOutputStream oos = new ObjectOutputStream(Files.newOutputStream(file))) {
            oos.writeObject(new ArrayList<>(completedAnalyses));
        } catch (Exception e) {
            logger.error("Failed to save completed analyses: {}", e.getMessage(), e);
        }
    }

    /**
     * Load rule cache from disk.
     */
    private void loadRuleCache() {
        Path file = storageDir.resolve(RULE_CACHE_FILE);
        if (!Files.exists(file)) {
            return;
        }

        try (BufferedReader reader = Files.newBufferedReader(file)) {
            lastRuleUpdateHash = reader.readLine();
            logger.debug("Loaded rule cache with hash: {}", lastRuleUpdateHash);
        } catch (Exception e) {
            logger.warn("Failed to load rule cache: {}", e.getMessage());
        }
    }

    /**
     * Save rule cache to disk.
     */
    private void saveRuleCache() {
        Path file = storageDir.resolve(RULE_CACHE_FILE);
        try (BufferedWriter writer = Files.newBufferedWriter(file)) {
            if (lastRuleUpdateHash != null) {
                writer.write(lastRuleUpdateHash);
            }
        } catch (Exception e) {
            logger.error("Failed to save rule cache: {}", e.getMessage(), e);
        }
    }

    /**
     * Update the rule cache hash.
     *
     * @param newHash the new rule hash
     */
    private void updateRuleCache(String newHash) {
        this.lastRuleUpdateHash = newHash;
        saveRuleCache();
    }

    /**
     * Get the last rule update hash.
     *
     * @return the hash or null if not set
     */
    public String getLastRuleUpdateHash() {
        return lastRuleUpdateHash;
    }
}