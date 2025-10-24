# OWASP ZAP AI Plugin

An OWASP ZAP extension that provides comprehensive AI-specific security testing capabilities for web applications that interact with AI services.

## Current Status

**Version**: 1.0.0-alpha
**ZAP Compatibility**: 2.16.0
**Build Status**: ✅ Compiles successfully

### Implemented Features ✅

- **ZAP 2.16.0 API Compatibility**: Fully updated for latest ZAP API
- **Core Extension Framework**: AIExtension.java with proper hook integration
- **Passive Scan Rules**: AIPassiveScanRules.java for traffic analysis without additional requests
- **API Implementation**: AIApiImplementor.java providing REST endpoints for AI security operations
- **Backend Integration**: BackendClient.java for secure API key authentication and content submission
- **AI Traffic Detection**: AIDetector.java for identifying AI service endpoints and analyzing HTTP traffic
- **Scan Controller**: AIScanController.java for managing scan operations and results

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
│                    ZAP Extension API                        │
├─────────────────────────────────────────────────────────────┤
│  Passive Scan Rules • API Endpoints • Backend Integration  │
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

#### 3. Backend Integration
- **Status**: ✅ Implemented in BackendClient.java
- **Description**: Secure submission of suspicious content to backend service
- **Features**:
  - API key authentication
  - Content submission with metadata
  - Error handling and retry logic
  - Configurable submission filters

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

### PII Filter (🚧 Critical Requirement)

#### Overview
- **Status**: 🚧 Not yet implemented (critical for production use)
- **Purpose**: Filter Personal Identifiable Information before submitting content to AI service
- **Importance**: Prevents accidental exposure of sensitive user data

#### Required PII Patterns
```java
// Example PII patterns to detect and filter:
- Email addresses: user@example.com
- Phone numbers: (555) 123-4567, +1-555-123-4567
- Social Security Numbers: 123-45-6789
- Credit card numbers: 4111-1111-1111-1111
- IP addresses: 192.168.1.1
- API keys and tokens
- Database connection strings
- Internal system identifiers
```

#### Implementation Plan
```java
public class PIIFilter {
    private List<Pattern> piiPatterns;
    private Map<String, String> replacementRules;

    public String filterPII(String content) {
        // Detect and mask/replace PII before submission
        // Return filtered content safe for AI service submission
    }

    public List<PIIDetection> detectPII(String content) {
        // Return list of detected PII with severity levels
    }
}
```

#### Configuration
```yaml
pii_filter:
  enabled: true
  severity_levels:
    - email: medium
    - phone: high
    - ssn: critical
    - credit_card: critical
  replacement_strategy: mask  # mask, remove, or replace
  custom_patterns:
    - pattern: "internal_id_\\d+"
      severity: high
```

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
```

#### Backend Integration Configuration

```bash
# Configure API key for backend submissions
curl "http://localhost:8080/JSON/ai/action/configureBackend/" \
  -d "apiKey=your-api-key" \
  -d "backendUrl=https://api.tavoai.net" \
  -d "submitSuspicious=true" \
  -d "submitBorderline=false"
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

# Get results
results = zap.ai.results(scan_id)
threats = zap.ai.threats()
status = zap.ai.status()
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

### Phase 2: Security Features (🚧 In Progress)
- [ ] **PII Filter Implementation** (Critical Priority)
  - Email, phone, SSN, credit card detection
  - Configurable filtering rules
  - Multiple replacement strategies (mask, remove, replace)
- [ ] Active scan rules rewrite for ZAP 2.16.0
- [ ] Prompt injection testing
- [ ] Model manipulation detection

### Phase 3: Advanced Features (📋 Planned)
- [ ] Real-time monitoring dashboard
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

### Known Limitations
- No custom rule configuration
- No advanced reporting formats
- No real-time monitoring capabilities
- Limited AI service detection patterns
- No content safety validation

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