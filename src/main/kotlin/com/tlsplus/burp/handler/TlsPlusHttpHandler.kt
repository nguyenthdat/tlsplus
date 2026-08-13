package com.tlsplus.burp.handler

import burp.api.montoya.http.HttpService
import burp.api.montoya.http.handler.HttpHandler
import burp.api.montoya.http.handler.HttpRequestToBeSent
import burp.api.montoya.http.handler.HttpResponseReceived
import burp.api.montoya.http.handler.RequestToBeSentAction
import burp.api.montoya.http.handler.ResponseReceivedAction
import burp.api.montoya.http.message.requests.HttpRequest
import com.tlsplus.burp.settings.ExtensionSettings

/**
 * HTTP-level handler — redirects outgoing traffic through the local Rust proxy
 * server for TLS fingerprint spoofing.
 *
 * This handler fires for ALL Burp HTTP traffic (Proxy, Repeater, Scanner, etc.).
 * When enabled, requests are rewritten to go through the local TLS+ proxy server
 * on `127.0.0.1:<port>` with forwarding headers that tell the Rust proxy which
 * TLS profile to use and where to forward.
 */
class TlsPlusHttpHandler(
    private val settings: ExtensionSettings,
) : HttpHandler {
    override fun handleHttpRequestToBeSent(requestToBeSent: HttpRequestToBeSent): RequestToBeSentAction {
        if (settings.passThroughOnly) return RequestToBeSentAction.continueWith(requestToBeSent)

        // Skip requests to our own proxy server (avoid loops)
        val host = requestToBeSent.httpService().host()
        if (host == "127.0.0.1" || host == "localhost") {
            return RequestToBeSentAction.continueWith(requestToBeSent)
        }

        return try {
            val (proxyHost, proxyPort) = parseProxyAddr()
            val proxyService = HttpService.httpService(proxyHost, proxyPort, false)

            val targetUrl = buildTargetUrl(requestToBeSent.url())

            val redirected =
                if (requestToBeSent.httpVersion().equals("HTTP/2", ignoreCase = true)) {
                    HttpRequest
                        .http2Request(proxyService, requestToBeSent.headers(), requestToBeSent.body())
                        .withHeader("X-Tlsplus-Http-Version", "HTTP/2")
                } else {
                    requestToBeSent
                        .withService(proxyService)
                        .withRemovedHeader("X-Tlsplus-Http-Version")
                }.withHeader("X-Tlsplus-Target", targetUrl)
                    .withHeader("X-Tlsplus-Profile", settings.profileName)
                    .withHeader("X-Tlsplus-Timeout", "30")

            RequestToBeSentAction.continueWith(redirected)
        } catch (e: Exception) {
            RequestToBeSentAction.continueWith(requestToBeSent)
        }
    }

    override fun handleHttpResponseReceived(responseReceived: HttpResponseReceived): ResponseReceivedAction =
        ResponseReceivedAction.continueWith(responseReceived)

    // ── Helpers ──────────────────────────────────────────────────────

    private fun parseProxyAddr(): Pair<String, Int> {
        val addr = settings.serverListenAddr
        val colon = addr.lastIndexOf(':')
        return if (colon > 0) {
            Pair(addr.substring(0, colon), addr.substring(colon + 1).toIntOrNull() ?: 43117)
        } else {
            Pair(addr, 43117)
        }
    }

    private fun buildTargetUrl(url: String): String =
        if (
            url.startsWith("http://") ||
            url.startsWith("https://") ||
            url.startsWith("ws://") ||
            url.startsWith("wss://")
        ) {
            url
        } else {
            "https://$url"
        }
}
