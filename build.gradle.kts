import java.security.MessageDigest
import com.github.spotbugs.snom.Confidence
import com.github.spotbugs.snom.Effort
import com.github.spotbugs.snom.SpotBugsTask

plugins {
    kotlin("jvm") version "2.4.21"
    kotlin("plugin.spring") version "2.4.21"
    id("org.springframework.boot") version "4.1.2"
    id("com.github.spotbugs") version "6.5.12"
    id("org.owasp.dependencycheck") version "13.0.0"
}

group = "ru.itmo.infosec"
version = "1.0.0"

repositories { mavenCentral() }
kotlin {
    jvmToolchain(21)
    compilerOptions { freeCompilerArgs.add("-Xjsr305=strict") }
}

dependencies {
    // Constrain application dependencies without overriding the separate SpotBugs tool classpath.
    implementation(platform(org.springframework.boot.gradle.plugin.SpringBootPlugin.BOM_COORDINATES))
    implementation(platform("org.jetbrains.kotlin:kotlin-bom:2.4.21"))
    implementation("org.springframework.boot:spring-boot-starter-webmvc")
    implementation("org.springframework.boot:spring-boot-starter-security")
    implementation("org.springframework.boot:spring-boot-starter-security-oauth2-resource-server")
    implementation("org.springframework.boot:spring-boot-starter-jdbc")
    implementation("org.springframework.boot:spring-boot-starter-validation")
    implementation("tools.jackson.module:jackson-module-kotlin")
    implementation("org.jetbrains.kotlin:kotlin-reflect")
    runtimeOnly("com.h2database:h2")
    testImplementation("org.springframework.boot:spring-boot-starter-webmvc-test")
    testImplementation("org.springframework.boot:spring-boot-starter-security-test")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
    spotbugsPlugins("com.h3xstream.findsecbugs:findsecbugs-plugin:1.14.0")
}

tasks.withType<Test>().configureEach { useJUnitPlatform() }
spotbugs {
    toolVersion.set("4.10.4")
    effort.set(Effort.MAX)
    reportLevel.set(Confidence.LOW)
    ignoreFailures.set(false)
    includeFilter.set(file("config/spotbugs/security-include.xml"))
    excludeFilter.set(file("config/spotbugs/reviewed-exclusions.xml"))
}
tasks.named<SpotBugsTask>("spotbugsMain") {
    reports.create("html") {
        required.set(true)
        outputLocation.set(layout.buildDirectory.file("reports/spotbugs/main.html"))
    }
    reports.create("xml") {
        required.set(true)
        outputLocation.set(layout.buildDirectory.file("reports/spotbugs/main.xml"))
    }
}
// Test fixtures are verified by JUnit. SAST scans production bytecode.
tasks.named<SpotBugsTask>("spotbugsTest") { enabled = false }

// SCA uses public NVD data. Keep it separate from ordinary offline-capable build/test.
dependencyCheck {
    formats.set(listOf("HTML", "JSON"))
    outputDirectory.set(layout.buildDirectory.dir("reports/dependency-check"))
    scanConfigurations.set(listOf("runtimeClasspath"))
    // Spring Boot runtimeClasspath inherits testAndDevelopmentOnly; it is still production runtime.
    skipTestGroups.set(false)
    failBuildOnCVSS.set(7.0F)
    failOnError.set(true)
    // Use the standard NVD REST API; the previous custom feed returned HTTP 404.
    // An optional key speeds up requests. Without it, the plugin applies its anonymous rate limit.
    providers.environmentVariable("NVD_API_KEY").orNull
        ?.takeIf { it.isNotBlank() }
        ?.let { nvd.apiKey.set(it) }
    nvd.maxRetryCount.set(3)
    // Supplementary OSS Index now requires credentials; NVD analysis remains enabled.
    analyzers.ossIndex.enabled.set(false)
}

// Do not accept a green report that silently skipped some or all runtime JARs.
tasks.named("dependencyCheckAnalyze") {
    outputs.upToDateWhen { false }
    doLast {
        val report = groovy.json.JsonSlurper().parse(
            layout.buildDirectory.file("reports/dependency-check/dependency-check-report.json").get().asFile
        ) as Map<*, *>
        val hashes = mutableSetOf<String>()
        fun collect(value: Any?) {
            when (value) {
                is Map<*, *> -> {
                    (value["sha256"] as? String)?.let { hashes.add(it.lowercase()) }
                    value.values.forEach { collect(it) }
                }

                is List<*> -> value.forEach { collect(it) }
            }
        }
        collect(report["dependencies"])
        val jars = configurations.getByName("runtimeClasspath").files.filter { it.extension == "jar" }
        check(jars.isNotEmpty()) { "SCA: runtimeClasspath contains no JARs" }
        val missing = jars.filter { jar ->
            val digest = MessageDigest.getInstance("SHA-256")
            jar.inputStream().use { input ->
                val buffer = ByteArray(8192)
                while (true) {
                    val count = input.read(buffer)
                    if (count < 0) break
                    digest.update(buffer, 0, count)
                }
            }
            digest.digest().joinToString("") { "%02x".format(it) } !in hashes
        }
        check(missing.isEmpty()) { "SCA missed runtime JARs: ${missing.joinToString { it.name }}" }
        logger.lifecycle("SCA coverage verified: ${jars.size} runtime JARs, all SHA-256 values present")
    }
}
