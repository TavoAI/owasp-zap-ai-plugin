package net.tavoai.zap.ai.api;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.zap.extension.api.ApiAction;
import org.zaproxy.zap.extension.api.ApiException;
import org.zaproxy.zap.extension.api.ApiImplementor;
import org.zaproxy.zap.extension.api.ApiResponse;
import org.zaproxy.zap.extension.api.ApiResponseElement;
import org.zaproxy.zap.extension.api.ApiResponseList;
import org.zaproxy.zap.extension.api.ApiResponseSet;

import net.tavoai.zap.ai.scan.AIScanController;
import net.tavoai.zap.ai.detector.AIDetector;
import net.tavoai.zap.ai.detector.PIIFilter;
import net.tavoai.zap.ai.model.AIThreat;
import net.tavoai.zap.ai.model.ScanResult;

import java.util.List;
import java.util.Map;
import java.util.HashMap;
import java.util.Arrays;

/**
 * API implementor for AI security extension.
 *
 * Provides REST API endpoints for AI security scanning and analysis.
 */
public class AIApiImplementor extends ApiImplementor {

    private static final Logger logger = LogManager.getLogger(AIApiImplementor.class);

    private static final String PREFIX = "ai";

    private final AIScanController scanController;
    private final AIDetector aiDetector;

    /**
     * Constructor.
     */
    public AIApiImplementor() {
        this.scanController = new AIScanController();
        this.aiDetector = new AIDetector();

        // Register API actions - ZAP 2.16.0 uses List<String> for parameters
        addApiAction(new ApiAction("scan", Arrays.asList("url"), Arrays.asList()));
        addApiAction(new ApiAction("analyze", Arrays.asList("url"), Arrays.asList()));
        addApiAction(new ApiAction("results", Arrays.asList("scanId"), Arrays.asList()));
        addApiAction(new ApiAction("threats", Arrays.asList(), Arrays.asList()));
        addApiAction(new ApiAction("status", Arrays.asList(), Arrays.asList()));
        // PII filtering actions
        addApiAction(new ApiAction("filterPII", Arrays.asList("content"), Arrays.asList()));
        addApiAction(new ApiAction("detectPII", Arrays.asList("content"), Arrays.asList()));
        addApiAction(new ApiAction("configurePII", Arrays.asList("enabled", "strategy"), Arrays.asList()));
    }

    @Override
    public String getPrefix() {
        return PREFIX;
    }

    public ApiResponse handleApiAction(String name, Map<String, String> parameters) throws ApiException {
        logger.debug("Handling API action: {} with parameters: {}", name, parameters);

        try {
            return switch (name) {
                case "scan" -> handleScanAction(parameters);
                case "analyze" -> handleAnalyzeAction(parameters);
                case "results" -> handleResultsAction(parameters);
                case "threats" -> handleThreatsAction(parameters);
                case "status" -> handleStatusAction(parameters);
                // PII filtering actions
                case "filterPII" -> handleFilterPIIAction(parameters);
                case "detectPII" -> handleDetectPIIAction(parameters);
                case "configurePII" -> handleConfigurePIIAction(parameters);
                default -> throw new ApiException(ApiException.Type.BAD_ACTION, "Unknown action: " + name);
            };
        } catch (Exception e) {
            logger.error("Error handling API action {}: {}", name, e.getMessage(), e);
            throw new ApiException(ApiException.Type.INTERNAL_ERROR, e.getMessage());
        }
    }

    /**
     * Handle scan action.
     *
     * @param parameters action parameters
     * @return API response
     */
    private ApiResponse handleScanAction(Map<String, String> parameters) throws ApiException {
        String targetUrl = parameters.get("url");
        if (targetUrl == null || targetUrl.isEmpty()) {
            throw new ApiException(ApiException.Type.MISSING_PARAMETER, "url parameter is required");
        }

        try {
            String scanId = scanController.startScan(targetUrl);

            // ZAP 2.16.0 ApiResponseSet constructor takes (String, Map)
            Map<String, String> responseData = new HashMap<>();
            responseData.put("scanId", scanId);
            responseData.put("status", "started");
            responseData.put("targetUrl", targetUrl);

            return new ApiResponseSet("scan", responseData);

        } catch (Exception e) {
            throw new ApiException(ApiException.Type.INTERNAL_ERROR, "Failed to start scan: " + e.getMessage());
        }
    }

    /**
     * Handle analyze action.
     *
     * @param parameters action parameters
     * @return API response
     */
    private ApiResponse handleAnalyzeAction(Map<String, String> parameters) throws ApiException {
        String url = parameters.get("url");
        if (url == null || url.isEmpty()) {
            throw new ApiException(ApiException.Type.MISSING_PARAMETER, "url parameter is required");
        }

        try {
            // Create a mock HTTP message for analysis
            HttpMessage mockMessage = createMockHttpMessage(url);
            List<AIThreat> threats = aiDetector.analyzeMessage(mockMessage);

            ApiResponseList response = new ApiResponseList("threats");
            for (AIThreat threat : threats) {
                // ZAP 2.16.0 ApiResponseSet constructor takes (String, Map)
                Map<String, String> threatData = new HashMap<>();
                threatData.put("type", threat.getType().toString());
                threatData.put("severity", threat.getSeverity().toString());
                threatData.put("description", threat.getDescription());
                threatData.put("evidence", threat.getEvidence());
                threatData.put("url", threat.getUrl());
                response.addItem(new ApiResponseSet("threat", threatData));
            }

            return response;

        } catch (Exception e) {
            throw new ApiException(ApiException.Type.INTERNAL_ERROR, "Failed to analyze URL: " + e.getMessage());
        }
    }

    /**
     * Handle results action.
     *
     * @param parameters action parameters
     * @return API response
     */
    private ApiResponse handleResultsAction(Map<String, String> parameters) throws ApiException {
        String scanId = parameters.get("scanId");
        if (scanId == null || scanId.isEmpty()) {
            throw new ApiException(ApiException.Type.MISSING_PARAMETER, "scanId parameter is required");
        }

        try {
            List<ScanResult> results = scanController.getScanResults(scanId);

            ApiResponseList response = new ApiResponseList("results");
            for (ScanResult result : results) {
                // ZAP 2.16.0 ApiResponseSet constructor takes (String, Map)
                Map<String, String> resultData = new HashMap<>();
                resultData.put("threatType", result.getThreatType());
                resultData.put("severity", result.getSeverity());
                resultData.put("url", result.getUrl());
                resultData.put("description", result.getDescription());
                resultData.put("evidence", result.getEvidence());
                resultData.put("timestamp", String.valueOf(result.getTimestamp()));
                response.addItem(new ApiResponseSet("result", resultData));
            }

            return response;

        } catch (Exception e) {
            throw new ApiException(ApiException.Type.INTERNAL_ERROR, "Failed to get results: " + e.getMessage());
        }
    }

    /**
     * Handle threats action.
     *
     * @param parameters action parameters
     * @return API response
     */
    private ApiResponse handleThreatsAction(Map<String, String> parameters) throws ApiException {
        try {
            List<ScanResult> allResults = scanController.getAllScanResults();

            ApiResponseList response = new ApiResponseList("allThreats");
            for (ScanResult result : allResults) {
                // ZAP 2.16.0 ApiResponseSet constructor takes (String, Map)
                Map<String, String> resultData = new HashMap<>();
                resultData.put("scanId", result.getScanId());
                resultData.put("threatType", result.getThreatType());
                resultData.put("severity", result.getSeverity());
                resultData.put("url", result.getUrl());
                resultData.put("description", result.getDescription());
                resultData.put("evidence", result.getEvidence());
                response.addItem(new ApiResponseSet("threat", resultData));
            }

            return response;

        } catch (Exception e) {
            throw new ApiException(ApiException.Type.INTERNAL_ERROR, "Failed to get threats: " + e.getMessage());
        }
    }

    /**
     * Handle status action.
     *
     * @param parameters action parameters
     * @return API response
     */
    private ApiResponse handleStatusAction(Map<String, String> parameters) throws ApiException {
        try {
            boolean isScanning = scanController.isScanning();

            // ZAP 2.16.0 ApiResponseSet constructor takes (String, Map)
            Map<String, String> statusData = new HashMap<>();
            statusData.put("scanning", String.valueOf(isScanning));
            statusData.put("totalScans", String.valueOf(scanController.getAllScanResults().size()));

            return new ApiResponseSet("status", statusData);

        } catch (Exception e) {
            throw new ApiException(ApiException.Type.INTERNAL_ERROR, "Failed to get status: " + e.getMessage());
        }
    }

    /**
     * Handle filter PII action.
     *
     * @param parameters action parameters
     * @return API response
     */
    private ApiResponse handleFilterPIIAction(Map<String, String> parameters) throws ApiException {
        String content = parameters.get("content");
        if (content == null || content.isEmpty()) {
            throw new ApiException(ApiException.Type.MISSING_PARAMETER, "content parameter is required");
        }

        try {
            String filteredContent = aiDetector.getPIIFilter().filterPII(content);

            // ZAP 2.16.0 ApiResponseSet constructor takes (String, Map)
            Map<String, String> responseData = new HashMap<>();
            responseData.put("originalLength", String.valueOf(content.length()));
            responseData.put("filteredLength", String.valueOf(filteredContent.length()));
            responseData.put("filteredContent", filteredContent);

            return new ApiResponseSet("piiFilter", responseData);

        } catch (Exception e) {
            throw new ApiException(ApiException.Type.INTERNAL_ERROR, "Failed to filter PII: " + e.getMessage());
        }
    }

    /**
     * Handle detect PII action.
     *
     * @param parameters action parameters
     * @return API response
     */
    private ApiResponse handleDetectPIIAction(Map<String, String> parameters) throws ApiException {
        String content = parameters.get("content");
        if (content == null || content.isEmpty()) {
            throw new ApiException(ApiException.Type.MISSING_PARAMETER, "content parameter is required");
        }

        try {
            List<PIIFilter.PIIDetection> detections = aiDetector.getPIIFilter().detectPII(content);

            ApiResponseList response = new ApiResponseList("piiDetections");
            for (PIIFilter.PIIDetection detection : detections) {
                // ZAP 2.16.0 ApiResponseSet constructor takes (String, Map)
                Map<String, String> detectionData = new HashMap<>();
                detectionData.put("type", detection.getType());
                detectionData.put("severity", detection.getSeverity().toString());
                detectionData.put("originalValue", detection.getOriginalValue());
                detectionData.put("startPosition", String.valueOf(detection.getStartPosition()));
                detectionData.put("endPosition", String.valueOf(detection.getEndPosition()));
                response.addItem(new ApiResponseSet("piiDetection", detectionData));
            }

            return response;

        } catch (Exception e) {
            throw new ApiException(ApiException.Type.INTERNAL_ERROR, "Failed to detect PII: " + e.getMessage());
        }
    }

    /**
     * Handle configure PII action.
     *
     * @param parameters action parameters
     * @return API response
     */
    private ApiResponse handleConfigurePIIAction(Map<String, String> parameters) throws ApiException {
        String enabledStr = parameters.get("enabled");
        String strategyStr = parameters.get("strategy");

        try {
            PIIFilter piiFilter = aiDetector.getPIIFilter();

            if (enabledStr != null) {
                boolean enabled = Boolean.parseBoolean(enabledStr);
                piiFilter.setEnabled(enabled);
            }

            if (strategyStr != null) {
                PIIFilter.ReplacementStrategy strategy = PIIFilter.ReplacementStrategy.valueOf(strategyStr.toUpperCase());
                piiFilter.setReplacementStrategy(strategy);
            }

            // ZAP 2.16.0 ApiResponseSet constructor takes (String, Map)
            Map<String, String> responseData = new HashMap<>();
            responseData.put("enabled", String.valueOf(piiFilter.isEnabled()));
            responseData.put("strategy", piiFilter.getReplacementStrategy().toString());

            return new ApiResponseSet("piiConfiguration", responseData);

        } catch (Exception e) {
            throw new ApiException(ApiException.Type.INTERNAL_ERROR, "Failed to configure PII filter: " + e.getMessage());
        }
    }

    /**
     * Create a mock HTTP message for analysis.
     *
     * @param url the URL to analyze
     * @return mock HTTP message
     */
    private HttpMessage createMockHttpMessage(String url) throws Exception {
        HttpRequestHeader header = new HttpRequestHeader();
        header.setMethod("POST");
        try {
            header.setURI(new org.apache.commons.httpclient.URI(url, false));
        } catch (org.apache.commons.httpclient.URIException e) {
            throw new ApiException(ApiException.Type.ILLEGAL_PARAMETER, "Invalid URL: " + e.getMessage());
        }
        header.setVersion(org.parosproxy.paros.network.HttpRequestHeader.HTTP11);
        header.setHeader("Content-Type", "application/json");
        header.setHeader("User-Agent", "ZAP AI Security Scanner");

        HttpMessage message = new HttpMessage(header);
        message.setRequestBody("{\"messages\": [{\"role\": \"user\", \"content\": \"Test message\"}]}");

        return message;
    }

    public ApiResponse handleApiView(String name, Map<String, String> parameters) throws ApiException {
        // No views implemented yet
        throw new ApiException(ApiException.Type.BAD_VIEW, "View not implemented: " + name);
    }
}