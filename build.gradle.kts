import org.zaproxy.gradle.addon.AddOnStatus

plugins {
    java
    id("org.zaproxy.add-on")
}

group = "org.zaproxy"
version = "1.0.0"

repositories {
    mavenCentral()
}

dependencies {
    zapAddOn("commonlib")

    implementation("org.apache.logging.log4j:log4j-core:2.17.1")

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.mockito:mockito-core:4.11.0")
}

zapAddOn {
    addOnName.set("AI Security Scanner")
    addOnStatus.set(AddOnStatus.BETA)

    manifest {
        author.set("TavoAI Security Team")
        url.set("https://github.com/tavoai/owasp-zap-ai-plugin")
        description.set("AI-powered security scanner for OWASP ZAP with active and passive scanning capabilities")

        extensions {
            register("net.tavoai.zap.ai.AIExtension") {
                classnames {
                    allowed.set(listOf("net.tavoai.zap.ai"))
                }
            }
        }
    }
}