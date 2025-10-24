# OWASP ZAP AI Plugin

An OWASP ZAP extension that provides comprehensive AI-specific security testing capabilities for web applications that interact with AI services.

## Current Status

**Version**: 1.0.0
**ZAP Compatibility**: 2.16.0
**Build Status**: ✅ Compiles successfully, ✅ All tests pass (10/10)

### Implemented Features ✅

- **ZAP 2.16.0 API Compatibility**: Fully updated for latest ZAP API
- **Core Extension Framework**: AIExtension.java with proper hook integration
- **Passive Scan Rules**: AIPassiveScanRules.java for traffic analysis without additional requests
- **API Implementation**: AIApiImplementor.java providing REST endpoints for AI security operations
- **Backend Integration**: BackendClient.java for secure API key authentication and content submission
- **AI Traffic Detection**: AIDetector.java for identifying AI service endpoints and analyzing HTTP traffic
- **Scan Controller**: AIScanController.java for managing scan operations and results
- **Backend Analysis Service**: BackendAnalysisService.java for automated rule updates and analysis result processing

### Features Yet To Implement 🚧

- **Active Scan Rules**: AIActiveScanRules.java (currently stubbed - requires major rewrite for ZAP 2.16.0 active scanner API)
- **PII Filter**: Personal Identifiable Information filtering for submissions to AI service
- **Prompt Injection Testing**: Active testing for prompt injection vulnerabilities
- **Model Manipulation Detection**: Tests for unauthorized AI model parameter changes
- **Data Exfiltration Prevention**: Detection of sensitive data extraction via AI responses
- **Rate Limiting Bypass Detection**: Testing for rate limit circumvention techniques
- **Content Safety Validation**: AI response safety and compliance checking
- **Adversarial Input Generation**: Automated generation of adversarial inputs
- **Real-time Monitoring Dashboard**: Live security metrics and alerts
- **Custom Rules Engine**: Extensible rule system for organization-specific policies
- **Advanced Reporting**: SARIF, HTML, and JSON report formats

### Immediate Priorities

1. **PII Filter Implementation** 🔴
   - Implement PII detection and filtering before AI service submissions
   - Support for common PII patterns (emails, phone numbers, SSNs, credit cards, etc.)
   - Configurable filtering rules and severity levels

2. **Active Scan Rules Completion** 🟡
   - Rewrite AIActiveScanRules.java for ZAP 2.16.0 active scanner framework
   - Implement prompt injection, model manipulation, and data exfiltration testing

3. **Enhanced Backend Integration** 🟢
   - Improve error handling and retry logic
   - Add content categorization and threat intelligence
   - Implement submission queuing and rate limiting

## Architecture

### Current Implementation
```
┌─────────────────────────────────────────────────────────────┐
│                    OWASP ZAP AI Plugin                      │
│                    (ZAP 2.16.0 Compatible)                 │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │ AIExtension │  │ Passive     │  │ API                 │ │
│  │   (✅)      │  │ Scan Rules  │  │ Implementor          │ │
│  │             │  │   (✅)      │  │   (✅)               │ │
│  └─────────────┘  └─────────────┘  └─────────────────────┘ │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │ AI Detector │  │ Scan        │  │ Backend Client      │ │
│  │   (✅)      │  │ Controller  │  │   (✅)              │ │
│  │             │  │   (✅)      │  │                     │ │
│  └─────────────┘  └─────────────┘  └─────────────────────┘ │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────────┐                                   │
│  │ Backend Analysis    │                                   │
│  │ Service   (✅)      │                                   │
│  │                     │                                   │
│  └─────────────────────┘                                   │
├─────────────────────────────────────────────────────────────┤
│                    ZAP Extension API                        │
├─────────────────────────────────────────────────────────────┤
│  Passive Scan Rules • API Endpoints • Backend Integration  │
│  • Automated Rule Updates • Analysis Result Processing     │
└─────────────────────────────────────────────────────────────┘
```

### Planned Architecture (Future Releases)
```
┌─────────────────────────────────────────────────────────────┐
│                    OWASP ZAP AI Plugin                      │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │ AI Scanner  │  │ Prompt      │  │ Adversarial        │ │
│  │   Engine    │  │ Injection   │  │ Input Generator     │ │
│  │             │  │   Tester    │  │                     │ │
│  └─────────────┘  └─────────────┘  └─────────────────────┘ │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │ Content     │  │ Rate Limit  │  │ Custom Rules       │ │
│  │ Safety      │  │   Tester    │  │ Engine             │ │
│  │ Validator   │  │             │  │                     │ │
│  └─────────────┘  └─────────────┘  └─────────────────────┘ │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │ PII Filter  │  │ Real-time   │  │ Advanced           │ │
│  │   (🚧)      │  │ Monitoring  │  │ Reporting          │ │
│  │             │  │ Dashboard   │  │                     │ │
│  └─────────────┘  └─────────────┘  └─────────────────────┘ │
├─────────────────────────────────────────────────────────────┤
│                    ZAP Extension API                        │
├─────────────────────────────────────────────────────────────┤
│  Active Scan Rules • Passive Scan Rules • Custom Scripts   │
└─────────────────────────────────────────────────────────────┘
```

## Supported AI Services

### Major AI Providers
- **OpenAI**: GPT-4, GPT-3.5, DALL-E, Whisper, TTS
- **Anthropic**: Claude 3 (Opus, Sonnet, Haiku), Claude 2
- **Google AI**: Gemini Pro/Ultra, PaLM 2, Vertex AI
- **Cohere**: Command, Generate, Embed
- **Meta**: Llama 2/3 (API access)
- **Mistral AI**: All models
- **Stability AI**: Stable Diffusion
- **Replicate**: Model hosting platform
- **Hugging Face**: Inference API

### Detection Methods

#### HTTP Traffic Analysis
```http
# OpenAI API Call Detection
POST /v1/chat/completions HTTP/1.1
Host: api.openai.com
Authorization: Bearer sk-...
Content-Type: application/json

# Request Body Analysis
{
  "model": "gpt-4",
  "messages": [{"role": "user", "content": "..."}],
  "temperature": 0.7
}
```

#### URL Pattern Matching
- `api.openai.com/v1/*`
- `api.anthropic.com/v1/messages`
- `generativelanguage.googleapis.com/v1beta/models/*`
- `api.cohere.ai/v1/generate`

#### Content-Type Analysis
- JSON payloads with AI-specific structures
- Streaming responses (SSE, WebSocket)
- Multipart form data for file uploads

## Scan Rules

### Passive Scan Rules (✅ Implemented)

#### 1. AI Service Detection
- **Status**: ✅ Fully implemented in AIPassiveScanRules.java
- **Description**: Identifies AI service usage in web applications
- **Detection Methods**:
  - HTTP traffic analysis for AI API endpoints
  - JavaScript library detection (openai.js, etc.)
  - API endpoint discovery
  - Response pattern analysis
  - Network traffic analysis

#### 2. AI Content Analysis
- **Status**: ✅ Implemented in AIDetector.java
- **Description**: Analyzes HTTP traffic for AI-specific security issues
- **Checks**:
  - Suspicious user agent patterns
  - Unusual request patterns
  - Potential data exfiltration attempts
  - Rate limiting analysis

#### 4. Backend Analysis Service
- **Status**: ✅ Fully implemented in BackendAnalysisService.java
- **Description**: Automated background service for rule updates and analysis result processing
- **Features**:
  - Periodic rule updates from backend (every 60 minutes)
  - Automatic analysis result retrieval (every 30 seconds)
  - Thread-safe service lifecycle management
  - Pending analysis tracking and cleanup
  - Configurable update intervals and concurrency limits

### Active Scan Rules (🚧 Planned)

#### 1. Prompt Injection Testing
- **Status**: 🚧 Stubbed in AIActiveScanRules.java (requires ZAP 2.16.0 active scanner rewrite)
- **Description**: Tests for prompt injection vulnerabilities
- **Attack Vectors**:
  - Direct prompt injection: `"; ignore previous; do malicious thing`
  - Context manipulation: Changing conversation context
  - System prompt override: Attempting to modify system instructions
  - Multi-turn injection: Building attacks across multiple requests

#### 2. Model Manipulation Testing
- **Status**: 🚧 Not implemented
- **Description**: Tests for AI model manipulation attempts
- **Attack Vectors**:
  - Parameter manipulation: Changing temperature, max_tokens, etc.
  - Model switching: Attempting to use different/unapproved models
  - Jailbreak attempts: Common jailbreak techniques
  - Adversarial inputs: Inputs designed to fool the model

#### 3. Data Exfiltration Testing
- **Status**: 🚧 Not implemented
- **Description**: Tests for sensitive data extraction via AI
- **Attack Vectors**:
  - Prompt-based extraction: Asking AI to reveal sensitive data
  - Response manipulation: Tricking AI into including sensitive info
  - Context poisoning: Injecting sensitive data into prompts
  - Memory extraction: Attempting to access conversation history

#### 4. Rate Limiting Bypass Testing
- **Status**: 🚧 Not implemented
- **Description**: Tests for rate limiting bypass techniques
- **Attack Vectors**:
  - Header manipulation: Changing API keys, tokens
  - Request splitting: Breaking requests into smaller parts
  - Timing attacks: Exploiting timing windows
  - Proxy abuse: Using proxies to bypass limits

### Backend Analysis Service

### Overview
The Backend Analysis Service (`BackendAnalysisService.java`) provides automated background processing for AI security analysis. This service runs continuously in the background and handles:

- **Periodic Rule Updates**: Automatically fetches and applies rule updates from the backend every 60 minutes
- **Analysis Result Processing**: Checks for completed analyses every 30 seconds and processes results
- **Service Lifecycle Management**: Thread-safe start/stop operations integrated with ZAP extension lifecycle
- **Pending Analysis Tracking**: Maintains a queue of submitted analyses and monitors their completion

### Key Features

#### Automated Rule Updates
```java
// Service automatically checks for rule updates every hour
private static final long RULE_UPDATE_INTERVAL_MINUTES = 60;

// Fetches updates from backend and applies them to the detector
private boolean performRuleUpdate() {
    Optional<String> ruleUpdates = backendClient.fetchRuleUpdates();
    if (ruleUpdates.isPresent()) {
        return applyRuleUpdates(ruleUpdates.get());
    }
    return false;
}
```

#### Analysis Result Processing
```java
// Checks analysis results every 30 seconds
private static final long ANALYSIS_CHECK_INTERVAL_SECONDS = 30;

// Processes completed analyses and updates detector
private int performAnalysisCheck() {
    // Check all pending analyses for completion
    // Process results and update threat intelligence
    // Clean up old/failed analyses
}
```

#### Persistent Storage
```java
// Data persists across ZAP restarts
private static final String PENDING_ANALYSES_FILE = "pending-analyses.dat";
private static final String COMPLETED_ANALYSES_FILE = "completed-analyses.dat";
private static final String RULE_CACHE_FILE = "rule-cache.dat";

// Storage location: ~/.ZAP/plugin-data/ai-plugin/
private Path getStorageDirectory() {
    String zapHome = System.getProperty("user.home") + "/.ZAP";
    return Paths.get(zapHome, "plugin-data", "ai-plugin");
}
```

#### Thread-Safe Operations
```java
// Atomic boolean for thread-safe state management
private final AtomicBoolean running = new AtomicBoolean(false);

// Read-write lock for thread-safe file operations
private final ReadWriteLock storageLock = new ReentrantReadWriteLock();
```

### Configuration

#### Service Intervals
```yaml
backend_analysis_service:
  rule_update_interval_minutes: 60    # Check for rule updates every hour
  analysis_check_interval_seconds: 30 # Check analysis results every 30 seconds
  max_concurrent_analyses: 10         # Maximum analyses to process per check
  analysis_timeout_hours: 24          # Remove analyses older than 24 hours
```

#### Backend Integration
```java
// Service integrates with existing backend configuration
BackendAnalysisService service = new BackendAnalysisService(config, aiDetector);
service.start(); // Starts automatic background processing
```

### Monitoring and Management

#### Service Status
```bash
# Check service status via API
curl "http://localhost:8080/JSON/ai/view/serviceStatus/"

# Response includes:
{
  "running": true,
  "backend_enabled": true,
  "pending_analyses": 5,
  "completed_analyses": 23,
  "last_rule_update": "2025-10-24T10:30:00Z",
  "last_analysis_check": "2025-10-24T10:32:15Z"
}
```

#### Manual Operations
```bash
# Force immediate rule update check
curl "http://localhost:8080/JSON/ai/action/forceRuleUpdate/"

# Force immediate analysis results check
curl "http://localhost:8080/JSON/ai/action/forceAnalysisCheck/"

# Response: {"processed": 3} // Number of analyses processed
```

### Integration with ZAP Lifecycle

The service is automatically integrated with the ZAP extension lifecycle:

```java
// In AIExtension.java
@Override
public void init() {
    // Initialize service
    backendAnalysisService = new BackendAnalysisService(config, detector);
    backendAnalysisService.start();
}

@Override
public void unload() {
    // Stop service during extension unload
    if (backendAnalysisService != null) {
        backendAnalysisService.stop();
    }
}
```

### Benefits

1. **Persistent State**: Analysis data survives ZAP restarts and system crashes
2. **Automated Updates**: Rules stay current without manual intervention
3. **Efficient Processing**: Background processing doesn't impact scanning performance
4. **Reliable Operation**: Thread-safe design prevents race conditions and data corruption
5. **Resource Management**: Automatic cleanup of old analyses and failed requests
6. **Incremental Updates**: Rule change detection prevents unnecessary processing
7. **Monitoring**: Comprehensive status reporting and manual override capabilities

### Data Persistence and Storage

The Backend Analysis Service implements robust data persistence to ensure analysis state survives ZAP restarts and system interruptions.

#### Storage Architecture

**File-Based Storage**:
```
~/.ZAP/plugin-data/ai-plugin/
├── pending-analyses.dat     # Serialized Map<String, Long> of pending analyses
├── completed-analyses.dat   # Serialized List<String> of completed analysis IDs
└── rule-cache.dat          # Text file with last rule update hash
```

**Storage Location**: `~/.ZAP/plugin-data/ai-plugin/` (Linux/Mac) or `%USERPROFILE%\.ZAP\plugin-data\ai-plugin\` (Windows)

#### Persistence Strategy

1. **Load on Startup**: All persistent data is loaded when the service initializes
2. **Save on Changes**: Data is saved after processing analysis results
3. **Save on Shutdown**: Complete state is saved when the service stops
4. **Thread-Safe Access**: Read-write locks prevent data corruption during concurrent access
5. **Error Recovery**: Service continues operating even if storage operations fail

#### Data Structures

**Pending Analyses** (`Map<String, Long>`):
- Key: Analysis ID (String)
- Value: Submission timestamp (Long, milliseconds since epoch)
- Automatically cleaned up after 24 hours

**Completed Analyses** (`List<String>`):
- Stores last 100 completed analysis IDs
- Used for duplicate detection and reporting
- Rotates out old entries to prevent unbounded growth

**Rule Cache** (`String`):
- Hash of last successfully applied rule update
- Prevents reprocessing identical rule updates
- Stored as plain text for easy inspection

#### Storage Operations

```java
// Thread-safe data loading
private void loadPersistentData() {
    storageLock.writeLock().lock();
    try {
        loadPendingAnalyses();
        loadCompletedAnalyses();
        loadRuleCache();
    } finally {
        storageLock.writeLock().unlock();
    }
}

// Automatic saving after analysis processing
if (processed > 0) {
    savePersistentData(); // Saves all state to disk
}
```

#### Benefits of File-Based Storage

1. **ZAP Native**: Uses ZAP's standard plugin data directory
2. **Cross-Platform**: Works on Windows, Mac, and Linux
3. **Human Readable**: Text files can be inspected manually
4. **Backup Friendly**: Easy to backup and restore
5. **No Database Dependency**: Doesn't require ZAP's internal database access
6. **Atomic Operations**: File operations are atomic where possible

#### Future Database Integration

While file-based storage is currently used for simplicity and reliability, future versions may migrate to ZAP's internal HSQLDB database for:
- Better performance with large datasets
- ACID transactions for data consistency
- Built-in backup and recovery features
- SQL querying capabilities for analytics

## Installation

### Prerequisites
- **OWASP ZAP 2.16.0** (required - updated for latest API)
- **Java 17** or later
- **Maven 3.6+** (for building from source)

### Current Build Status
- ✅ **Compiles successfully** with ZAP 2.16.0
- ✅ **Core functionality implemented** (passive scanning, API endpoints, backend integration)
- 🚧 **Active scanning stubbed** (requires major rewrite for ZAP 2.16.0 active scanner API)
- 🚧 **PII filter not yet implemented** (critical for production use)

### Installation Steps

1. **Clone Repository**
   ```bash
   git clone https://github.com/tavoai/owasp-zap-ai-plugin.git
   cd owasp-zap-ai-plugin
   ```

2. **Build Plugin**
   ```bash
   mvn clean compile
   ```

3. **Package for ZAP**
   ```bash
   mvn package
   ```

4. **Install via ZAP**
   - Open ZAP 2.16.0
   - Go to `File` → `Load Add-on File`
   - Select `target/zap-ai-plugin-1.0.0.jar`

### Development Setup

```bash
# Clone and build
git clone https://github.com/tavoai/owasp-zap-ai-plugin.git
cd owasp-zap-ai-plugin
mvn clean compile

# Run tests
mvn test

# Package for distribution
mvn package
```

## Usage

### Basic Scanning

1. **Start ZAP**
2. **Configure Target**
   - Set target URL in the "Sites" tree
3. **Run AI Scan**
   - Right-click target → "Attack" → "AI Security Scan"
   - Or use the "AI" menu → "Run AI Security Scan"

### Advanced Configuration

#### Scan Policy Configuration
```xml
<!-- zap-ai-policy.xml -->
<scanpolicy>
  <rules>
    <rule>
      <name>Prompt Injection</name>
      <enabled>true</enabled>
      <threshold>medium</threshold>
      <strength>high</strength>
    </rule>
    <rule>
      <name>Model Manipulation</name>
      <enabled>true</enabled>
      <threshold>low</threshold>
      <strength>medium</strength>
    </rule>
  </rules>
</scanpolicy>
```

#### Custom Rule Configuration
```yaml
# ai-scan-config.yaml
ai_scan:
  enabled_services:
    - openai
    - anthropic
    - google_ai

  custom_rules:
    - name: "Company Policy Check"
      pattern: "internal|confidential|secret"
      severity: high

  adversarial_inputs:
    enabled: true
    max_attempts: 100
    timeout_seconds: 30
```

### CI/CD Integration

#### GitHub Actions Example
```yaml
name: AI Security Scan
on: [push, pull_request]

jobs:
  ai-security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Run OWASP ZAP AI Scan
        uses: zaproxy/action-baseline@v0.8.0
        with:
          target: 'http://localhost:3000'
          rules_file_name: 'ai-scan-rules.yml'
          cmd_options: '-a'
```

#### Jenkins Pipeline Example
```groovy
pipeline {
    agent any

    stages {
        stage('AI Security Scan') {
            steps {
                script {
                    sh '''
                        docker run --rm -v $(pwd):/zap/wrk \
                        owasp/zap2docker-stable zap-baseline.py \
                        -t http://app:3000 \
                        -r ai-scan-report.html \
                        -c ai-scan-config.yml
                    '''
                }
            }
        }
    }
}
```

## API Integration

### ZAP API Endpoints (✅ Implemented)

The plugin provides REST API endpoints accessible via ZAP's API interface.

#### Available Endpoints

```bash
# Start AI security scan (passive scanning only)
curl "http://localhost:8080/JSON/ai/action/scan/" \
  -d "url=http://target-app.com"

# Analyze specific URL for AI threats
curl "http://localhost:8080/JSON/ai/action/analyze/" \
  -d "url=http://target-app.com/api/chat"

# Get scan results
curl "http://localhost:8080/JSON/ai/view/results/" \
  -d "scanId=12345"

# Get all detected AI threats
curl "http://localhost:8080/JSON/ai/view/threats/"

# Get current scan status
curl "http://localhost:8080/JSON/ai/view/status/"

# Backend Analysis Service Management
curl "http://localhost:8080/JSON/ai/action/forceRuleUpdate/"
curl "http://localhost:8080/JSON/ai/action/forceAnalysisCheck/"
curl "http://localhost:8080/JSON/ai/view/serviceStatus/"
```

#### Backend Integration Configuration

```bash
# Configure API key for backend submissions
curl "http://localhost:8080/JSON/ai/action/configureBackend/" \
  -d "apiKey=your-api-key" \
  -d "backendUrl=https://api.tavoai.net" \
  -d "submitSuspicious=true" \
  -d "submitBorderline=false"

# Backend Analysis Service Configuration
curl "http://localhost:8080/JSON/ai/action/configureService/" \
  -d "ruleUpdateIntervalMinutes=60" \
  -d "analysisCheckIntervalSeconds=30" \
  -d "maxConcurrentAnalyses=10"
```
```

### Python API Integration

```python
from zapv2 import ZAPv2

# Connect to ZAP
zap = ZAPv2(apikey='your-api-key')

# Configure backend integration
zap.ai.configure_backend(
    api_key='your-api-key',
    backend_url='https://api.tavoai.net',
    submit_suspicious=True,
    submit_borderline=False
)

# Start passive AI security scan
scan_id = zap.ai.scan(url='http://target-app.com')

# Get service status
results = zap.ai.service_status()
print(f"Service running: {results['running']}")
print(f"Pending analyses: {results['pending_count']}")
print(f"Completed analyses: {results['completed_count']}")

# Force immediate operations
zap.ai.force_rule_update()
processed = zap.ai.force_analysis_check()
print(f"Processed {processed} analysis results")
```
```

### Current Limitations

- **Active scanning not available**: Active scan rules are stubbed and require major rewrite for ZAP 2.16.0 compatibility
- **PII filtering not implemented**: Content submitted to backend may contain sensitive information
- **Limited rule coverage**: Only basic passive detection rules are implemented
- **No custom rule engine**: Cannot add organization-specific security rules yet

### Next Steps for API Enhancement

1. **Implement PII Filter** (Critical)
   ```java
   // Planned API endpoint
   POST /JSON/ai/action/filterPII/
   {
     "content": "User email: user@example.com",
     "filterLevel": "strict"
   }
   ```

2. **Active Scanning API**
   ```java
   // Planned active scan endpoints
   POST /JSON/ai/action/activeScan/
   POST /JSON/ai/action/testPromptInjection/
   POST /JSON/ai/action/testModelManipulation/
   ```

3. **Custom Rules API**
   ```java
   // Planned custom rule management
   POST /JSON/ai/action/addCustomRule/
   GET /JSON/ai/view/customRules/
   DELETE /JSON/ai/action/removeCustomRule/
   ```

## Development Roadmap

### Phase 1: Core Foundation (✅ Complete)
- [x] ZAP 2.16.0 API compatibility
- [x] Basic extension framework
- [x] Passive scan rules implementation
- [x] API endpoint implementation
- [x] Backend client integration
- [x] Backend analysis service with automated rule updates and analysis processing

### Phase 2: Security Features (🚧 In Progress)
- [ ] **PII Filter Implementation** (Critical Priority)
  - Email, phone, SSN, credit card detection
  - Configurable filtering rules
  - Multiple replacement strategies (mask, remove, replace)
- [ ] Active scan rules rewrite for ZAP 2.16.0
- [ ] Zap HSQLDB for rule storage, submission management, etc.
- [ ] Prompt injection testing
- [ ] Model manipulation detection

### Phase 3: Advanced Features (📋 Planned)
- [ ] Real-time monitoring dashboard UI integration
- [ ] Custom rules engine
- [ ] Advanced reporting (SARIF, HTML, JSON)
- [ ] Content safety validation
- [ ] Rate limiting bypass detection
- [ ] Adversarial input generation

### Phase 4: Enterprise Features (📋 Future)
- [ ] Distributed scanning support
- [ ] Cloud integration (AWS Lambda, Google Cloud Run)
- [ ] Kubernetes deployment
- [ ] Advanced analytics and threat intelligence
- [ ] Compliance reporting (OWASP LLM Top 10, ISO 42001)

## Current Issues & Limitations

### Critical Issues
1. **PII Filter Missing**: No filtering of sensitive data before backend submission
2. **Active Scanning Disabled**: Major rewrite required for ZAP 2.16.0 active scanner API
3. **Limited Rule Coverage**: Only basic passive detection implemented

### Current Limitations
- **Active scanning not available**: Active scan rules are stubbed and require major rewrite for ZAP 2.16.0 active scanner API
- **PII filtering not implemented**: Content submitted to backend may contain sensitive information
- **Limited rule coverage**: Only basic passive detection implemented
- **No custom rule engine**: Cannot add organization-specific security rules yet

### Workarounds
- Use passive scanning only for initial AI traffic detection
- Manually review content before enabling backend submission
- Implement PII filtering at application level until plugin feature is available

## Contributing

### Current Development Focus
We welcome contributions, especially for:
- **PII Filter Implementation** (High Priority)
- **Active Scan Rules Rewrite** (High Priority)
- **Additional AI Service Detection Patterns**
- **Test Coverage Improvements**

### Development Setup
```bash
# Clone repository
git clone https://github.com/tavoai/owasp-zap-ai-plugin.git
cd owasp-zap-ai-plugin

# Build and test
mvn clean compile test

# Run with ZAP for testing
# (Requires ZAP 2.16.0 installation)
```

### Contribution Guidelines
1. **Fork and create feature branch**
2. **Add tests for new functionality**
3. **Ensure all tests pass**: `mvn test`
4. **Update documentation** for any new features
5. **Submit pull request** with clear description

### Code Standards
- Java 17 compatibility required
- Follow existing code patterns
- Add JavaDoc for public methods
- Include unit tests for new functionality
- Update README for significant changes

## Testing

### Current Test Coverage
- ✅ Core extension loading
- ✅ Passive scan rules
- ✅ API endpoint functionality
- ✅ Backend client integration
- 🚧 Active scan rules (stubbed)
- 🚧 PII filtering (not implemented)

### Running Tests
```bash
# Unit tests
mvn test

# Integration tests (requires ZAP running)
mvn verify

# With coverage report
mvn test jacoco:report
```

## License

MIT License - see LICENSE file for details

## Support & Documentation

- **Documentation**: https://docs.owasp-zap-ai-plugin.com
- **Issues**: https://github.com/tavoai/owasp-zap-ai-plugin/issues
- **Discussions**: https://github.com/tavoai/owasp-zap-ai-plugin/discussions
- **Current Status**: Alpha release - core functionality implemented, production features pending

---

**Last Updated**: October 24, 2025
**Version**: 1.0.0-alpha
**ZAP Compatibility**: 2.16.0