package com.tlsplus.burp.handler

import burp.api.montoya.proxy.http.InterceptedRequest
import burp.api.montoya.proxy.http.ProxyRequestHandler
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction
import com.tlsplus.burp.settings.ExtensionSettings

/**
 * Proxy-level handler — captures header order for HTTP/2 fingerprinting.
 *
 * The actual TLS redirect is handled by [TlsPlusHttpHandler] which fires
 * at a lower level and works correctly for both browser and Repeater traffic.
 */
class TlsPlusProxyHandler(
    private val settings: ExtensionSettings,
    private val log: (String) -> Unit = {},
) : ProxyRequestHandler {
    override fun handleRequestReceived(interceptedRequest: InterceptedRequest): ProxyRequestReceivedAction =
        ProxyRequestReceivedAction.continueWith(interceptedRequest)

    override fun handleRequestToBeSent(request: InterceptedRequest): ProxyRequestToBeSentAction {
        if (settings.preserveHeaderOrder) {
            try {
                val ordered = request.headers().map { it.name() }
                log("Header order (${ordered.size}): ${ordered.take(8).joinToString(", ")}...")
            } catch (_: Exception) {
            }
        }
        return ProxyRequestToBeSentAction.continueWith(request)
    }
}
