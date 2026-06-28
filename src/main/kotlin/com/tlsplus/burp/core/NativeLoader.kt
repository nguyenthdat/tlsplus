package com.tlsplus.burp.core

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption

object NativeLoader {
    private const val LIBRARY_NAME = "tlsplus_core"

    @Volatile
    private var loaded = false

    fun ensureLoaded(log: (String) -> Unit = {}) {
        if (loaded) return

        synchronized(this) {
            if (loaded) return

            val mappedName = System.mapLibraryName(LIBRARY_NAME)
            val platform = platformClassifier()
            val resourcePath = "/native/$platform/$mappedName"
            val stream = NativeLoader::class.java.getResourceAsStream(resourcePath)

            if (stream != null) {
                val extractionDir = Files.createDirectories(
                    Path.of(System.getProperty("java.io.tmpdir"), "tlsplus-native", platform),
                )
                val target = extractionDir.resolve(mappedName)
                stream.use { input ->
                    Files.copy(input, target, StandardCopyOption.REPLACE_EXISTING)
                }
                target.toFile().deleteOnExit()
                prependJnaLibraryPath(extractionDir)
                System.load(target.toAbsolutePath().toString())
                loaded = true
                log("Loaded TLS+ native library from $target")
                return
            }

            log("Native resource $resourcePath not found; falling back to java.library.path")
            System.loadLibrary(LIBRARY_NAME)
            loaded = true
        }
    }

    private fun prependJnaLibraryPath(dir: Path) {
        val separator = System.getProperty("path.separator")
        val existing = System.getProperty("jna.library.path")
        val updated = if (existing.isNullOrBlank()) {
            dir.toAbsolutePath().toString()
        } else {
            dir.toAbsolutePath().toString() + separator + existing
        }
        System.setProperty("jna.library.path", updated)
    }

    private fun platformClassifier(): String {
        val osName = System.getProperty("os.name").lowercase()
        val archName = System.getProperty("os.arch").lowercase()

        val os = when {
            osName.contains("mac") || osName.contains("darwin") -> "darwin"
            osName.contains("linux") -> "linux"
            osName.contains("windows") -> "windows"
            else -> osName.replace(Regex("[^a-z0-9]+"), "-")
        }

        val arch = when (archName) {
            "aarch64", "arm64" -> "aarch64"
            "x86_64", "amd64" -> "x86_64"
            else -> archName
        }

        return "$os-$arch"
    }
}
