package com.tlsplus.burp

import burp.api.montoya.BurpExtension
import burp.api.montoya.MontoyaApi
import com.tlsplus.burp.core.TlsPlusCore
import com.tlsplus.burp.handler.TlsPlusHttpHandler
import com.tlsplus.burp.handler.TlsPlusProxyHandler
import com.tlsplus.burp.settings.ExtensionSettings
import com.tlsplus.burp.ui.TlsPlusSettingsPanel
import com.tlsplus.burp.ui.TlsPlusTab
import javax.swing.SwingUtilities
import kotlin.concurrent.thread

class TlsPlusExtension : BurpExtension {
    override fun initialize(api: MontoyaApi) {
        api.extension().setName("TLS+")

        val settings = ExtensionSettings(api.persistence().preferences())
        val log: (String) -> Unit = { message -> api.logging().logToOutput(message) }
        val core = TlsPlusCore(log)
        val tab = TlsPlusTab(core, settings, log)

        // ── UI ─────────────────────────────────────────────────────────
        api.userInterface().applyThemeToComponent(tab)
        api.userInterface().registerSuiteTab("TLS+", tab)

        // Native Burp Settings dialog panel, backed by the same ExtensionSettings
        // (Preferences) the handlers read — single source of truth.
        api.userInterface().registerSettingsPanel(TlsPlusSettingsPanel(settings, core))

        // ── Handlers ───────────────────────────────────────────────────
        // HttpHandler: redirects ALL outgoing traffic through Rust proxy
        api.http().registerHttpHandler(TlsPlusHttpHandler(settings))

        // ProxyRequestHandler: captures header order (lightweight)
        api.proxy().registerRequestHandler(TlsPlusProxyHandler(settings, log))

        // ── Auto-start proxy server ────────────────────────────────────
        // Start the embedded proxy server automatically so TLS fingerprint
        // spoofing works immediately without manual "Start Proxy" click.
        thread(name = "tlsplus-autostart", isDaemon = true) {
            // Small delay to let Burp fully initialize
            Thread.sleep(1000)

            val addr = settings.serverListenAddr
            log("TLS+ auto-starting proxy on $addr...")

            var result = core.startServer(addr)
            log(result)

            // If default port is busy, try fallback ports
            if (result.contains("already running")) {
                // Already started from previous session — fine
            } else if (!result.contains("RUNNING")) {
                for (port in 43118..43122) {
                    val fallback = "127.0.0.1:$port"
                    log("TLS+ retrying on $fallback...")
                    result = core.startServer(fallback)
                    if (result.contains("RUNNING")) {
                        settings.serverListenAddr = fallback
                        log("TLS+ proxy started on fallback port $fallback")
                        break
                    }
                }
            }

            // Nudge the header to reflect the live state immediately; the tab's
            // polling timer would catch it within ~2s regardless.
            SwingUtilities.invokeLater { tab.refreshStatus() }
        }

        // ── Cleanup on unload ──────────────────────────────────────────
        api.extension().registerUnloadingHandler {
            val status = core.stopServer()
            log("TLS+ unloaded — server: $status")
        }

        log("TLS+ v${core.shortStatus()} loaded — huginn-net-tls JA4 engine")
        log("Profiles: ${core.profiles().joinToString(", ")}")
    }
}
