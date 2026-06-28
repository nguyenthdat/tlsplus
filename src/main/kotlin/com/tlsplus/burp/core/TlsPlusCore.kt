package com.tlsplus.burp.core

import com.tlsplus.core.EngineInfo
import com.tlsplus.core.Ja3Result
import com.tlsplus.core.Ja4Result
import com.tlsplus.core.ProxyRequest
import com.tlsplus.core.ProxyResponse
import com.tlsplus.core.ServerStatus
import com.tlsplus.core.TlsProfileInfo
import com.tlsplus.core.availableProfiles
import com.tlsplus.core.engineInfo
import com.tlsplus.core.getTlsProfile
import com.tlsplus.core.ja3CalculateClientHello
import com.tlsplus.core.ja4CalculateClientHello
import com.tlsplus.core.proxySendRequest
import com.tlsplus.core.startLocalServer
import com.tlsplus.core.stopLocalServer
import com.tlsplus.core.tlsplusVersion
import java.util.UUID

class TlsPlusCore(
    private val log: (String) -> Unit = {},
) {
    // ---------------------------------------------------------------------------
    // Decorator: ensures the native library is loaded before every FFI call.
    // Eliminates repeated NativeLoader.ensureLoaded(log) + runCatching
    // boilerplate across all public methods (7 call sites → 1 guard point).
    // ---------------------------------------------------------------------------

    private inline fun <T> withNative(
        crossinline block: () -> T,
        fallback: (Throwable) -> T,
    ): T =
        runCatching {
            NativeLoader.ensureLoaded(log)
            block()
        }.getOrElse(fallback)

    // ── Core info ────────────────────────────────────────────────────────

    fun shortStatus(): String =
        withNative(
            block = { "native v${tlsplusVersion()}" },
            fallback = { "native unavailable: ${it.message}" },
        )

    fun describeCore(): String =
        withNative(
            block = {
                val info: EngineInfo = engineInfo()
                buildString {
                    appendLine("${info.`name`} v${info.`version`}")
                    appendLine("JA4 engine: ${info.`ja4Core`}")
                    appendLine("Reference: ${info.`foxioReference`}")
                    appendLine()
                    appendLine("Capabilities:")
                    info.`capabilities`.forEach { appendLine("  - $it") }
                    appendLine()
                    appendLine("Limitations:")
                    info.`limitations`.forEach { appendLine("  - $it") }
                }
            },
            fallback = { "Native core unavailable: ${it.stackTraceToString()}" },
        )

    fun profiles(): List<String> =
        withNative(
            block = { availableProfiles() },
            fallback = {
                log("Cannot load native profiles: ${it.message}")
                listOf("pass-through")
            },
        )

    // ── Server lifecycle ────────────────────────────────────────────────

    fun startServer(listenAddr: String): String =
        withNative(
            block = {
                val status: ServerStatus = startLocalServer(listenAddr)
                buildString {
                    appendLine("Server: ${if (status.`running`) "RUNNING" else "STOPPED"}")
                    appendLine("Listen: ${status.`listenAddr` ?: "n/a"}")
                    appendLine(status.`message`)
                }
            },
            fallback = { "failed to start server: ${it.message}" },
        )

    fun stopServer(): String =
        withNative(
            block = {
                val status: ServerStatus = stopLocalServer()
                buildString {
                    appendLine("Server: ${if (status.`running`) "RUNNING" else "STOPPED"}")
                    appendLine("Previous: ${status.`listenAddr` ?: "n/a"}")
                    appendLine(status.`message`)
                }
            },
            fallback = { "failed to stop server: ${it.message}" },
        )

    /**
     * Non-mutating query of the live embedded-server state. Returns null if the
     * native library is unavailable or the query fails, so callers can treat
     * "unknown" as "not running" without throwing.
     */
    fun serverStatus(): ServerStatus? =
        withNative(
            // Fully qualified to disambiguate from this same-named wrapper method
            // (the import `com.tlsplus.core.serverStatus` is the FFI entry point).
            block = { com.tlsplus.core.serverStatus() },
            fallback = {
                log("Cannot query server status: ${it.message}")
                null
            },
        )

    /** Convenience: true only when the embedded server reports it is running. */
    fun isServerRunning(): Boolean = serverStatus()?.`running` ?: false

    // ── Profile queries ──────────────────────────────────────────────────

    fun profileInfo(name: String): TlsProfileInfo? =
        withNative(
            block = { getTlsProfile(name) },
            fallback = {
                log("Cannot get profile info for '$name': ${it.message}")
                null
            },
        )

    // ── JA3 computation (legacy) ─────────────────────────────────────────

    fun computeJa3ClientHello(hex: String): String =
        withNative(
            block = {
                val bytes = parseHex(hex)
                val result: Ja3Result = ja3CalculateClientHello(bytes)
                formatJa3Result(result)
            },
            fallback = { "failed to compute JA3: ${it.message}" },
        )

    // ── JA4 computation from raw ClientHello hex ─────────────────────────

    fun computeClientHelloHex(hex: String): String =
        withNative(
            block = {
                val bytes = parseHex(hex)
                val result: Ja4Result = ja4CalculateClientHello(bytes)
                formatJa4Result(result)
            },
            fallback = { "failed to compute JA4 from hex: ${it.message}" },
        )

    fun computeClientHelloBytes(bytes: ByteArray): Ja4Result =
        withNative(
            block = { ja4CalculateClientHello(bytes) },
            fallback = {
                Ja4Result(
                    ok = false,
                    ja4 = null,
                    ja4R = null,
                    ja4O = null,
                    ja4Or = null,
                    ja4S1 = null,
                    ja4S1r = null,
                    sni = null,
                    alpn = null,
                    tlsVersion = null,
                    error = it.message,
                    source = "tlsplus-core (error)",
                )
            },
        )

    // ── Proxy request forwarding ─────────────────────────────────────────

    fun sendProxyRequest(
        method: String,
        url: String,
        headers: List<String>,
        body: ByteArray,
        profile: String,
        timeoutSecs: Int,
    ): ProxyResponse =
        withNative(
            block = {
                val request =
                    ProxyRequest(
                        id = UUID.randomUUID().toString(),
                        method = method,
                        url = url,
                        headers = headers,
                        body = body,
                        profile = profile,
                        timeoutSecs = timeoutSecs.toUInt(),
                    )
                proxySendRequest(request)
            },
            fallback = {
                ProxyResponse(
                    id = "",
                    statusCode = 0u,
                    headers = emptyList(),
                    body = ByteArray(0),
                    ja4 = null,
                    error = "proxySendRequest failed: ${it.message}",
                )
            },
        )

    // ── Helpers ──────────────────────────────────────────────────────────

    private fun formatJa3Result(r: Ja3Result): String =
        buildString {
            if (!r.`ok`) {
                appendLine("JA3 computation FAILED: ${r.`error` ?: "unknown error"}")
                return@buildString
            }
            appendLine("JA3:     ${r.`ja3` ?: "n/a"}")
            appendLine("JA3 MD5: ${r.`ja3Hash` ?: "n/a"}")
        }

    private fun formatJa4Result(r: Ja4Result): String =
        buildString {
            if (!r.`ok`) {
                appendLine("JA4 computation FAILED: ${r.`error` ?: "unknown error"}")
                appendLine("source: ${r.`source`}")
                return@buildString
            }
            appendLine("TLS Version: ${r.`tlsVersion` ?: "unknown"}")
            appendLine("SNI: ${r.`sni` ?: "(none)"}")
            appendLine("ALPN: ${r.`alpn` ?: "(none)"}")
            appendLine()
            appendLine("── JA4 Fingerprints ──")
            appendLine("JA4:     ${r.`ja4` ?: "n/a"}")
            appendLine("JA4_r:   ${r.`ja4R` ?: "n/a"}")
            appendLine("JA4_o:   ${r.`ja4O` ?: "n/a"}")
            appendLine("JA4_or:  ${r.`ja4Or` ?: "n/a"}")
            appendLine("JA4_s1:  ${r.`ja4S1` ?: "n/a"}")
            appendLine("JA4_s1r: ${r.`ja4S1r` ?: "n/a"}")
            appendLine()
            appendLine("source: ${r.`source`}")
        }

    private fun parseHex(input: String): ByteArray {
        val clean = input.replace(Regex("[^0-9a-fA-F]"), "")
        require(clean.length % 2 == 0) { "hex input must contain an even number of hex characters" }
        return ByteArray(clean.length / 2) { index ->
            clean.substring(index * 2, index * 2 + 2).toInt(16).toByte()
        }
    }
}
