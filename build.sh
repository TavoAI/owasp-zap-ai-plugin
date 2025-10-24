#!/bin/bash

# OWASP ZAP AI Plugin Build Script
# This script builds the AI security testing extension for OWASP ZAP

set -e

echo "Building OWASP ZAP AI Plugin..."

# Check if Maven is installed
if ! command -v mvn &> /dev/null; then
    echo "Error: Maven is not installed. Please install Maven to build this project."
    exit 1
fi

# Clean previous build
echo "Cleaning previous build..."
mvn clean

# Compile the project
echo "Compiling project..."
mvn compile

# Run tests
echo "Running tests..."
mvn test

# Package the extension
echo "Packaging extension..."
mvn package

# Check if build was successful
if [ -f "target/owasp-zap-ai-plugin-1.0.0.jar" ]; then
    echo "Build successful!"
    echo "Extension JAR: target/owasp-zap-ai-plugin-1.0.0.jar"
    echo ""
    echo "To install the extension in ZAP:"
    echo "1. Copy the JAR file to ZAP's plugin directory"
    echo "2. Restart ZAP"
    echo "3. The AI Security Testing extension will be available"
else
    echo "Build failed!"
    exit 1
fi