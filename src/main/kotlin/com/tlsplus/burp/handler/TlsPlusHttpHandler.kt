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
    private val proxyEndpoint: () -> String?,
) : HttpHandler {
    override fun handleHttpRequestToBeSent(requestToBeSent: HttpRequestToBeSent): RequestToBeSentAction {
        if (settings.passThroughOnly) return RequestToBeSentAction.continueWith(requestToBeSent)

        return try {
            val endpoint = proxyEndpoint() ?: return RequestToBeSentAction.continueWith(requestToBeSent)
            val (proxyHost, proxyPort) = parseProxyAddr(endpoint)
            val requestService = requestToBeSent.httpService()
            if (sameEndpointHost(requestService.host(), proxyHost) && requestService.port() == proxyPort) {
                return RequestToBeSentAction.continueWith(requestToBeSent)
            }
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

    private fun parseProxyAddr(address: String): Pair<String, Int> {
        val host: String
        val portText: String
        if (address.startsWith("[")) {
            val closingBracket = address.indexOf(']')
            require(closingBracket > 1 && address.getOrNull(closingBracket + 1) == ':') {
                "Invalid IPv6 proxy address: $address"
            }
            host = address.substring(1, closingBracket)
            portText = address.substring(closingBracket + 2)
        } else {
            val colon = address.lastIndexOf(':')
            require(colon > 0) { "Invalid proxy address: $address" }
            host = address.substring(0, colon)
            portText = address.substring(colon + 1)
        }
        val port = portText.toIntOrNull()
        require(port != null && port in 1..65535) { "Invalid proxy port: $portText" }
        return Pair(normalizeHost(host), port)
    }

    private fun normalizeHost(host: String): String = host.removePrefix("[").removeSuffix("]").lowercase()

    private fun sameEndpointHost(
        requestHost: String,
        proxyHost: String,
    ): Boolean {
        val request = normalizeHost(requestHost).replace("0:0:0:0:0:0:0:1", "::1")
        val proxy = normalizeHost(proxyHost).replace("0:0:0:0:0:0:0:1", "::1")
        return request == proxy ||
            (request == "localhost" && isLoopbackLiteral(proxy)) ||
            (proxy == "localhost" && isLoopbackLiteral(request))
    }

    private fun isLoopbackLiteral(host: String): Boolean = host == "::1" || host.startsWith("127.")

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
