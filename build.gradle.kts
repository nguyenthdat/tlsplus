import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    kotlin("jvm") version "2.3.21"
    `java-library`
}

group = "com.tlsplus"
version = "0.1.0"

val rustCrateDir = layout.projectDirectory.dir("crates/tlsplus-core")
val rustManifest = rustCrateDir.file("Cargo.toml")
val generatedKotlinDir = layout.buildDirectory.dir("generated/uniffi/kotlin")
val generatedResourcesDir = layout.buildDirectory.dir("generated/resources/main")
val prebuiltNativeBundleDir =
    providers
        .gradleProperty("tlsplus.nativeBundleDir")
        .map { file(it) }

fun currentNativePlatform(): String {
    val os = System.getProperty("os.name").lowercase()
    val arch = System.getProperty("os.arch").lowercase()
    val normalizedArch =
        when (arch) {
            "aarch64", "arm64" -> "aarch64"
            "x86_64", "amd64" -> "x86_64"
            else -> arch
        }

    val normalizedOs =
        when {
            os.contains("mac") || os.contains("darwin") -> "darwin"
            os.contains("linux") -> "linux"
            os.contains("windows") -> "windows"
            else -> os.replace(Regex("[^a-z0-9]+"), "-")
        }

    return "$normalizedOs-$normalizedArch"
}

fun nativeLibraryFileName(): String {
    val os = System.getProperty("os.name").lowercase()
    return when {
        os.contains("mac") || os.contains("darwin") -> "libtlsplus_core.dylib"
        os.contains("windows") -> "tlsplus_core.dll"
        else -> "libtlsplus_core.so"
    }
}

val nativePlatform = currentNativePlatform()
val nativeLibraryFileName = nativeLibraryFileName()
val nativeLibraryPath = layout.projectDirectory.file("target/release/$nativeLibraryFileName")

dependencies {
    compileOnly("net.portswigger.burp.extensions:montoya-api:2026.4")

    implementation("net.java.dev.jna:jna:5.19.1")

    testImplementation(kotlin("test"))
}

kotlin {
    jvmToolchain(21)
}

sourceSets {
    main {
        kotlin.srcDir(generatedKotlinDir)
        resources.srcDir(generatedResourcesDir)
    }
}

val cargoBuildRelease =
    tasks.register<Exec>("cargoBuildRelease") {
        description = "Builds the Rust UniFFI cdylib in release mode."
        group = "rust"
        workingDir = rustCrateDir.asFile
        inputs.files(
            fileTree(rustCrateDir) {
                include("Cargo.toml", "Cargo.lock", "uniffi.toml", "uniffi-bindgen.rs", "src/**/*.rs")
            },
        )
        outputs.file(nativeLibraryPath)
        commandLine(
            "cargo",
            "build",
            "--release",
            "--manifest-path",
            rustManifest.asFile.absolutePath,
        )
    }

val generateUniFfiBindings =
    tasks.register<Exec>("generateUniFfiBindings") {
        description = "Generates Kotlin bindings from the Rust UniFFI metadata."
        group = "uniffi"
        workingDir = rustCrateDir.asFile
        dependsOn(cargoBuildRelease)
        inputs.file(nativeLibraryPath)
        outputs.dir(generatedKotlinDir)
        doFirst {
            delete(generatedKotlinDir)
        }
        commandLine(
            "cargo",
            "run",
            "--manifest-path",
            rustManifest.asFile.absolutePath,
            "--bin",
            "uniffi-bindgen",
            "--",
            "generate",
            "--library",
            nativeLibraryPath.asFile.absolutePath,
            "--language",
            "kotlin",
            "--out-dir",
            generatedKotlinDir.get().asFile.absolutePath,
        )
    }

val copyNativeLibrary =
    tasks.register<Copy>("copyNativeLibrary") {
        description = "Copies the current platform Rust cdylib into jar resources."
        group = "rust"
        dependsOn(cargoBuildRelease)
        onlyIf {
            !prebuiltNativeBundleDir.isPresent
        }
        from(nativeLibraryPath)
        into(generatedResourcesDir.map { it.dir("native/$nativePlatform") })
    }

val copyPrebuiltNativeLibraries =
    tasks.register<Copy>("copyPrebuiltNativeLibraries") {
        description = "Copies prebuilt cross-platform Rust cdylibs from -Ptlsplus.nativeBundleDir into jar resources."
        group = "rust"

        onlyIf {
            val root = prebuiltNativeBundleDir.orNull ?: return@onlyIf false
            if (!root.exists()) {
                throw GradleException(
                    "Property -Ptlsplus.nativeBundleDir must point to a directory containing native/<platform>/<library> files.",
                )
            }
            true
        }

        prebuiltNativeBundleDir.orNull?.let { root ->
            val nativeRoot = root.resolve("native")
            from(if (nativeRoot.isDirectory) nativeRoot else root)
        }
        into(generatedResourcesDir.map { it.dir("native") })
    }

val copyNativeLibraries =
    tasks.register("copyNativeLibraries") {
        description = "Copies current-platform and optional prebuilt cross-platform native libraries into jar resources."
        group = "rust"
        dependsOn(copyNativeLibrary, copyPrebuiltNativeLibraries)
    }

tasks.withType<KotlinCompile>().configureEach {
    dependsOn(generateUniFfiBindings)
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_21)
        freeCompilerArgs.add("-Xjsr305=strict")
    }
}

tasks.processResources {
    dependsOn(copyNativeLibraries)
}

tasks.test {
    useJUnitPlatform()
}

tasks.jar {
    archiveBaseName.set("tlsplus-extension-thin")
}

val burpJar =
    tasks.register<Jar>("burpJar") {
        description = "Builds a Burp-loadable fat jar with Kotlin/JNA and native resources."
        group = "build"
        dependsOn(tasks.classes)
        archiveFileName.set("tlsplus-extension.jar")
        duplicatesStrategy = DuplicatesStrategy.EXCLUDE

        from(sourceSets.main.get().output)
        from({
            configurations.runtimeClasspath
                .get()
                .filter { it.name.endsWith(".jar") }
                .map { zipTree(it) }
        })
    }

tasks.assemble {
    dependsOn(burpJar)
}
