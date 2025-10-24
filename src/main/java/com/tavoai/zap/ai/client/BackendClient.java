package com.tavoai.zap.ai.client;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.core5.http.ClassicHttpResponse;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.http.io.entity.StringEntity;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import com.tavoai.zap.ai.model.ThreatType;
import com.tavoai.zap.ai.model.ThreatSeverity;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.HashMap;
import java.util.Optional;

/**
 * HTTP client for communicating with the TavoAI backend.
 *
 * Handles API key authentication, content submission, and rule updates.
 */
public class BackendClient {

    private static final Logger logger = LogManager.getLogger(BackendClient.class);

    private static final String DEFAULT_BASE_URL = "https://api.tavoai.net";
    private static final String API_VERSION = "v1";

    private final CloseableHttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final String baseUrl;
    private final String apiKey;

    /**
     * Constructor.
     *
     * @param apiKey the API key for authentication
     * @param baseUrl the base URL for the backend API
     */
    public BackendClient(String apiKey, String baseUrl) {
        this.apiKey = apiKey;
        this.baseUrl = baseUrl != null ? baseUrl : DEFAULT_BASE_URL;
        this.httpClient = HttpClients.createDefault();
        this.objectMapper = new ObjectMapper();

        logger.info("Backend client initialized - URL: {}, API Key: {}", this.baseUrl, apiKey != null ? "***" : "none");
    }

    /**
     * Submit content for backend analysis.
     *
     * @param content the content to analyze
     * @param threatType the detected threat type
     * @param severity the threat severity
     * @param sourceUrl the source URL
     * @return analysis result or empty if failed
     */
    public Optional<String> submitForAnalysis(String content, ThreatType threatType, ThreatSeverity severity, String sourceUrl) {
        try {
            String endpoint = String.format("%s/%s/ai/analyze", baseUrl, API_VERSION);

            Map<String, Object> payload = new HashMap<>();
            payload.put("content", content);
            payload.put("threatType", threatType.toString());
            payload.put("severity", severity.toString());
            payload.put("sourceUrl", sourceUrl);
            payload.put("client", "zap-plugin");

            String jsonPayload = objectMapper.writeValueAsString(payload);

            HttpPost post = new HttpPost(endpoint);
            post.setHeader("Authorization", "Bearer " + apiKey);
            post.setHeader("Content-Type", "application/json");
            post.setEntity(new StringEntity(jsonPayload, ContentType.APPLICATION_JSON, false));

            try (ClassicHttpResponse response = httpClient.execute(post)) {
                int statusCode = response.getCode();
                HttpEntity entity = response.getEntity();
                String responseBody = entity != null ? EntityUtils.toString(entity) : "";

                if (statusCode == 200) {
                    JsonNode jsonResponse = objectMapper.readTree(responseBody);
                    String analysisId = jsonResponse.path("analysisId").asText();
                    logger.debug("Content submitted for analysis, ID: {}", analysisId);
                    return Optional.of(analysisId);
                } else {
                    logger.warn("Failed to submit content for analysis - Status: {}, Response: {}", statusCode, responseBody);
                    return Optional.empty();
                }
            }

        } catch (Exception e) {
            logger.error("Error submitting content for analysis: {}", e.getMessage(), e);
            return Optional.empty();
        }
    }

    /**
     * Fetch rule updates from the backend.
     *
     * @return rule updates or empty if failed
     */
    public Optional<String> fetchRuleUpdates() {
        try {
            String endpoint = String.format("%s/%s/ai/rules", baseUrl, API_VERSION);

            HttpGet get = new HttpGet(endpoint);
            get.setHeader("Authorization", "Bearer " + apiKey);

            try (ClassicHttpResponse response = httpClient.execute(get)) {
                int statusCode = response.getCode();
                HttpEntity entity = response.getEntity();
                String responseBody = entity != null ? EntityUtils.toString(entity) : "";

                if (statusCode == 200) {
                    logger.info("Successfully fetched rule updates");
                    return Optional.of(responseBody);
                } else {
                    logger.warn("Failed to fetch rule updates - Status: {}, Response: {}", statusCode, responseBody);
                    return Optional.empty();
                }
            }

        } catch (Exception e) {
            logger.error("Error fetching rule updates: {}", e.getMessage(), e);
            return Optional.empty();
        }
    }

    /**
     * Get analysis results for a specific analysis ID.
     *
     * @param analysisId the analysis ID
     * @return analysis results or empty if not ready/failed
     */
    public Optional<String> getAnalysisResults(String analysisId) {
        try {
            String endpoint = String.format("%s/%s/ai/analysis/%s", baseUrl, API_VERSION, analysisId);

            HttpGet get = new HttpGet(endpoint);
            get.setHeader("Authorization", "Bearer " + apiKey);

            try (ClassicHttpResponse response = httpClient.execute(get)) {
                int statusCode = response.getCode();
                HttpEntity entity = response.getEntity();
                String responseBody = entity != null ? EntityUtils.toString(entity) : "";

                if (statusCode == 200) {
                    logger.debug("Retrieved analysis results for ID: {}", analysisId);
                    return Optional.of(responseBody);
                } else if (statusCode == 202) {
                    // Analysis still in progress
                    logger.debug("Analysis still in progress for ID: {}", analysisId);
                    return Optional.of("analysis_pending");
                } else {
                    logger.warn("Failed to get analysis results - Status: {}, Response: {}", statusCode, responseBody);
                    return Optional.empty();
                }
            }

        } catch (Exception e) {
            logger.error("Error getting analysis results: {}", e.getMessage(), e);
            return Optional.empty();
        }
    }

    /**
     * Validate API key with the backend.
     *
     * @return true if API key is valid
     */
    public boolean validateApiKey() {
        try {
            String endpoint = String.format("%s/%s/auth/validate", baseUrl, API_VERSION);

            HttpGet get = new HttpGet(endpoint);
            get.setHeader("Authorization", "Bearer " + apiKey);

            try (ClassicHttpResponse response = httpClient.execute(get)) {
                int statusCode = response.getCode();

                if (statusCode == 200) {
                    logger.info("API key validated successfully");
                    return true;
                } else {
                    logger.warn("API key validation failed - Status: {}", statusCode);
                    return false;
                }
            }

        } catch (Exception e) {
            logger.error("Error validating API key: {}", e.getMessage(), e);
            return false;
        }
    }

    /**
     * Get customer-specific configuration from the backend.
     *
     * @return customer configuration or empty if failed
     */
    public Optional<String> getCustomerConfig() {
        try {
            String endpoint = String.format("%s/%s/customer/config", baseUrl, API_VERSION);

            HttpGet get = new HttpGet(endpoint);
            get.setHeader("Authorization", "Bearer " + apiKey);

            try (ClassicHttpResponse response = httpClient.execute(get)) {
                int statusCode = response.getCode();
                HttpEntity entity = response.getEntity();
                String responseBody = entity != null ? EntityUtils.toString(entity) : "";

                if (statusCode == 200) {
                    logger.info("Retrieved customer configuration");
                    return Optional.of(responseBody);
                } else {
                    logger.warn("Failed to get customer config - Status: {}, Response: {}", statusCode, responseBody);
                    return Optional.empty();
                }
            }

        } catch (Exception e) {
            logger.error("Error getting customer config: {}", e.getMessage(), e);
            return Optional.empty();
        }
    }

    /**
     * Close the HTTP client and release resources.
     */
    public void close() {
        try {
            httpClient.close();
            logger.info("Backend client closed");
        } catch (IOException e) {
            logger.error("Error closing HTTP client: {}", e.getMessage());
        }
    }
}