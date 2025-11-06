// Builds a Ghidra Extension for a given Ghidra installation.
//
// An absolute path to the Ghidra installation directory must be supplied either via:
// * GHIDRA_INSTALL_DIR environment variable
// * gradle.properties file in project root with GHIDRA_INSTALL_DIR property

plugins {
    kotlin("jvm") version "2.2.21"
    kotlin("plugin.serialization") version "2.2.21"
    id("com.gradleup.shadow") version "9.2.2"
    id("com.github.ben-manes.versions") version "0.53.0"  // For checking dependency updates
    idea
}

group = "io.github.nonsleepr"

// Extract version from git tags or commit hash
val gitVersion: String by lazy {
    try {
        val process = Runtime.getRuntime().exec(arrayOf("git", "describe", "--tags", "--always", "--dirty"))
        val output = process.inputStream.bufferedReader().readText().trim()
        process.waitFor()
        if (process.exitValue() == 0 && output.isNotEmpty()) {
            // Remove 'v' prefix if present (e.g., v1.0.1 -> 1.0.1)
            output.removePrefix("v")
        } else {
            "1.0-SNAPSHOT"
        }
    } catch (e: Exception) {
        println("Warning: Could not determine git version, using default: ${e.message}")
        "1.0-SNAPSHOT"
    }
}

version = gitVersion

repositories {
    mavenCentral()
}

//----------------------START "DO NOT MODIFY" SECTION------------------------------
val ghidraInstallDir = System.getenv("GHIDRA_INSTALL_DIR")
    ?: project.findProperty("GHIDRA_INSTALL_DIR")?.toString()
    ?: throw GradleException("GHIDRA_INSTALL_DIR is not defined! Set it in gradle.properties or as environment variable.")

// Apply Ghidra's buildExtension script
apply(from = File(ghidraInstallDir).canonicalPath + "/support/buildExtension.gradle")
//----------------------END "DO NOT MODIFY" SECTION-------------------------------

// Disable copyDependencies task to prevent pollution of lib/ directory
tasks.named("copyDependencies") {
    enabled = false
}

kotlin {
    jvmToolchain(21)
}

dependencies {
    // MCP Kotlin SDK (correct version from Maven Central)
    implementation("io.modelcontextprotocol:kotlin-sdk:0.7.4")
    
    // Ktor Server for SSE transport
    implementation("io.ktor:ktor-server-core-jvm:3.3.2")
    implementation("io.ktor:ktor-server-netty-jvm:3.3.2")
    implementation("io.ktor:ktor-server-sse-jvm:3.3.2")
    
    // Kotlinx Serialization
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.9.0")
    
    // Kotlinx Coroutines
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.10.2")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-swing:1.10.2")
    
    // Logging - use Ghidra's SLF4J and Log4j
    compileOnly("org.slf4j:slf4j-api:2.0.16")
    implementation("org.apache.logging.log4j:log4j-slf4j-impl:2.17.1")
    
    // Ghidra JARs - use GHIDRA_INSTALL_DIR or fallback to lib directory
    // Use compileOnly since Ghidra provides these at runtime
    val ghidraDir = File(ghidraInstallDir, "Ghidra")
    if (ghidraDir.exists()) {
        // Use JARs directly from Ghidra installation
        compileOnly(files(
            "$ghidraDir/Framework/Generic/lib/Generic.jar",
            "$ghidraDir/Framework/SoftwareModeling/lib/SoftwareModeling.jar",
            "$ghidraDir/Framework/Project/lib/Project.jar",
            "$ghidraDir/Framework/Docking/lib/Docking.jar",
            "$ghidraDir/Features/Decompiler/lib/Decompiler.jar",
            "$ghidraDir/Framework/Utility/lib/Utility.jar",
            "$ghidraDir/Features/Base/lib/Base.jar",
            "$ghidraDir/Framework/Gui/lib/Gui.jar"
        ))
    } else {
        // Fallback to local lib directory (for backward compatibility)
        compileOnly(fileTree("lib") { include("*.jar") })
    }
    
    // Test dependencies
    testImplementation(kotlin("test"))
}

tasks.test {
    useJUnitPlatform()
}

// Configure processResources to replace version tokens in resource files
tasks.processResources {
    // Expand version in all .properties and MANIFEST.MF files
    filesMatching(listOf("**/*.properties", "**/MANIFEST.MF")) {
        expand(
            "version" to project.version.toString(),
            "projectVersion" to project.version.toString()
        )
    }
}

// Make version available at runtime via system property
tasks.withType<JavaExec> {
    systemProperty("kghidramcp.version", project.version.toString())
}

// Configure the JAR task
tasks.jar {
    archiveBaseName.set("KGhidraMCP")
    archiveVersion.set("")
    
    // Use custom manifest
    manifest {
        from("src/main/resources/META-INF/MANIFEST.MF")
    }
    
    // Exclude App class if present
    exclude("**/App.class")
}

// Configure Shadow JAR to create a fat JAR with all dependencies
tasks.shadowJar {
    archiveBaseName.set("KGhidraMCP")
    archiveClassifier.set("")
    archiveVersion.set("")  // No version suffix
    
    // Enable zip64 for large archives
    isZip64 = true
    
    // Use custom manifest
    manifest {
        from("src/main/resources/META-INF/MANIFEST.MF")
    }
    
    // Configure which dependencies to include (exclude Ghidra JARs and old lib/ directory)
    configurations = listOf(project.configurations.runtimeClasspath.get())
    
    // Enable minimization to remove unused classes
    minimize {
        // Exclude Ghidra JARs from minimization - they're provided at runtime
        exclude(dependency(".*:Generic:.*"))
        exclude(dependency(".*:SoftwareModeling:.*"))
        exclude(dependency(".*:Project:.*"))
        exclude(dependency(".*:Docking:.*"))
        exclude(dependency(".*:Decompiler:.*"))
        exclude(dependency(".*:Utility:.*"))
        exclude(dependency(".*:Base:.*"))
        exclude(dependency(".*:Gui:.*"))
    }
    
    // Relocate packages to avoid conflicts with Ghidra
    relocate("kotlin", "io.github.nonsleepr.mcp.shaded.kotlin")
    relocate("kotlinx", "io.github.nonsleepr.mcp.shaded.kotlinx")
    relocate("io.ktor", "io.github.nonsleepr.mcp.shaded.ktor")
    relocate("io.modelcontextprotocol", "io.github.nonsleepr.mcp.shaded.mcp")
    
    // Exclude Ghidra dependencies (already in Ghidra) - exclude all Ghidra-related packages
    exclude("ghidra/**")
    exclude("generic/**")
    exclude("docking/**")
    exclude("help/**")
    exclude("resources/**")
    exclude("utility/**")
    exclude("mdemangler/**")
    exclude("sarif/**")
    
    // Merge service files (important for Ktor and other frameworks)
    mergeServiceFiles()
    
    // Exclude signatures to avoid security exceptions
    exclude("META-INF/*.SF")
    exclude("META-INF/*.DSA")
    exclude("META-INF/*.RSA")
}

// Create our custom extension packaging task
// This replaces the default buildExtension from Ghidra
tasks.register<Zip>("packageExtension") {
    group = "distribution"
    description = "Package the Ghidra extension with fat JAR"
    
    // Declare explicit dependencies
    dependsOn(tasks.shadowJar, tasks.jar)
    
    archiveBaseName.set("KGhidraMCP")
    archiveVersion.set("")
    archiveClassifier.set("")
    destinationDirectory.set(file("dist"))
    
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    
    into("KGhidraMCP") {
        // Extension metadata
        from("src/main/resources/extension.properties")
        from("src/main/resources/Module.manifest")
        
        // Fat JAR in lib directory
        into("lib") {
            from(tasks.shadowJar.get().archiveFile)
        }
    }
}

// Override the default buildExtension task to use our package
tasks.named("buildExtension") {
    dependsOn("packageExtension")
    enabled = false
}

// Make build depend on our packaging
tasks.named("build") {
    dependsOn("packageExtension")
}

// IntelliJ IDEA configuration
idea {
    module {
        isDownloadSources = true
        isDownloadJavadoc = true
    }
}