// Builds a Ghidra Extension for a given Ghidra installation.
//
// An absolute path to the Ghidra installation directory must be supplied either via:
// * GHIDRA_INSTALL_DIR environment variable
// * gradle.properties file in project root with GHIDRA_INSTALL_DIR property

plugins {
    kotlin("jvm") version "2.1.0"
    kotlin("plugin.serialization") version "2.1.0"
    id("com.gradleup.shadow") version "8.3.5"
    idea
}

group = "io.github.nonsleepr"
version = "1.0-SNAPSHOT"

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

kotlin {
    jvmToolchain(21)
}

dependencies {
    // MCP Kotlin SDK (correct version from Maven Central)
    implementation("io.modelcontextprotocol:kotlin-sdk:0.7.4")
    
    // Ktor Server for SSE transport
    implementation("io.ktor:ktor-server-core-jvm:3.0.3")
    implementation("io.ktor:ktor-server-netty-jvm:3.0.3")
    implementation("io.ktor:ktor-server-sse-jvm:3.0.3")
    
    // Kotlinx Serialization
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.7.3")
    
    // Kotlinx Coroutines
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.9.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-swing:1.9.0")
    
    // Logging
    implementation("org.slf4j:slf4j-api:2.0.16")
    implementation("ch.qos.logback:logback-classic:1.5.12")
    
    // Ghidra JARs - use GHIDRA_INSTALL_DIR or fallback to lib directory
    val ghidraDir = File(ghidraInstallDir, "Ghidra")
    if (ghidraDir.exists()) {
        // Use JARs directly from Ghidra installation
        implementation(files(
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
        implementation(fileTree("lib") { include("*.jar") })
    }
    
    // Test dependencies
    testImplementation(kotlin("test"))
}

tasks.test {
    useJUnitPlatform()
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
    
    // Relocate packages to avoid conflicts with Ghidra
    relocate("kotlin", "io.github.nonsleepr.mcp.shaded.kotlin")
    relocate("kotlinx", "io.github.nonsleepr.mcp.shaded.kotlinx")
    relocate("io.ktor", "io.github.nonsleepr.mcp.shaded.ktor")
    relocate("io.modelcontextprotocol", "io.github.nonsleepr.mcp.shaded.mcp")
    relocate("org.slf4j", "io.github.nonsleepr.mcp.shaded.slf4j")
    relocate("ch.qos.logback", "io.github.nonsleepr.mcp.shaded.logback")
    
    // Exclude Ghidra dependencies (already in Ghidra)
    exclude("ghidra/**")
    
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