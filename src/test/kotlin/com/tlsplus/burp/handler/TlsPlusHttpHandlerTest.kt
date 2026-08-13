package com.tlsplus.burp.handler

import burp.api.montoya.core.ByteArray
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.handler.HttpRequestToBeSent
import burp.api.montoya.http.handler.RequestToBeSentAction
import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.internal.MontoyaObjectFactory
import burp.api.montoya.internal.ObjectFactoryLocator
import burp.api.montoya.persistence.Preferences
import com.tlsplus.burp.settings.ExtensionSettings
import java.lang.reflect.Method
import java.lang.reflect.Proxy
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertSame

class TlsPlusHttpHandlerTest {
    @Test
    fun builds_explicit_http2_request_for_the_local_proxy() {
        // Given: an HTTP/2 Montoya request and an active TLS+ handler.
        val factory = MontoyaFactoryFixture()
        val previous = ObjectFactoryLocator.FACTORY
        ObjectFactoryLocator.FACTORY = factory.proxy
        try {
            val handler = TlsPlusHttpHandler(ExtensionSettings(preferences()))
            val request = factory.request("HTTP/2")

            // When: the handler redirects the request to TLS+.
            val redirected = handler.handleHttpRequestToBeSent(request).request()

            // Then: Montoya receives an explicit HTTP/2 request with the downgrade guard.
            assertEquals(1, factory.http2Requests)
            assertSame(factory.sourceHeaders, factory.capturedHttp2Headers)
            assertSame(factory.sourceBody, factory.capturedHttp2Body)
            assertEquals(
                listOf(
                    ":method" to "CONNECT",
                    ":scheme" to "https",
                    ":authority" to "example.com",
                    ":path" to "/socket",
                    ":protocol" to "websocket",
                    "x-request-fixture" to "preserved",
                ),
                factory.capturedHttp2Headers?.map { it.name() to it.value() },
            )
            assertEquals("HTTP/2", redirected.httpVersion())
            assertEquals("127.0.0.1", redirected.httpService().host())
            assertEquals(43117, redirected.httpService().port())
            assertEquals("HTTP/2", redirected.headerValue("X-Tlsplus-Http-Version"))
            assertEquals("https://example.com/socket", redirected.headerValue("X-Tlsplus-Target"))
        } finally {
            ObjectFactoryLocator.FACTORY = previous
        }
    }

    @Test
    fun keeps_http1_on_the_existing_redirect_path() {
        // Given: an HTTP/1.1 Montoya request and an active TLS+ handler.
        val factory = MontoyaFactoryFixture()
        val previous = ObjectFactoryLocator.FACTORY
        ObjectFactoryLocator.FACTORY = factory.proxy
        try {
            val handler = TlsPlusHttpHandler(ExtensionSettings(preferences()))
            val request = factory.request("HTTP/1.1")

            // When: the handler redirects the request to TLS+.
            val redirected = handler.handleHttpRequestToBeSent(request).request()

            // Then: no HTTP/2 request or downgrade guard is introduced.
            assertEquals(0, factory.http2Requests)
            assertEquals("HTTP/1.1", redirected.httpVersion())
            assertEquals("127.0.0.1", redirected.httpService().host())
            assertEquals(null, redirected.headerValue("X-Tlsplus-Http-Version"))
        } finally {
            ObjectFactoryLocator.FACTORY = previous
        }
    }

    private fun preferences(): Preferences =
        proxy { method, _ ->
            when (method.name) {
                "getBoolean" -> {
                    false
                }

                "getString" -> {
                    when (method.parameterTypes.firstOrNull()) {
                        String::class.java -> null
                        else -> null
                    }
                }

                else -> {
                    defaultValue(method.returnType)
                }
            }
        }
}

private class MontoyaFactoryFixture {
    var http2Requests: Int = 0
        private set

    val sourceHeaders: List<HttpHeader> =
        listOf(
            header(":method", "CONNECT"),
            header(":scheme", "https"),
            header(":authority", "example.com"),
            header(":path", "/socket"),
            header(":protocol", "websocket"),
            header("x-request-fixture", "preserved"),
        )
    val sourceBody: ByteArray = proxy { method, _ -> defaultValue(method.returnType) }
    var capturedHttp2Headers: List<HttpHeader>? = null
        private set
    var capturedHttp2Body: ByteArray? = null
        private set

    val proxy: MontoyaObjectFactory =
        proxy { method, arguments ->
            when (method.name) {
                "httpService" -> {
                    service(arguments)
                }

                "http2Request" -> {
                    http2Requests += 1
                    @Suppress("UNCHECKED_CAST")
                    capturedHttp2Headers = arguments[1] as List<HttpHeader>
                    capturedHttp2Body = arguments[2] as ByteArray
                    requestProxy(
                        RequestState(
                            service = arguments[0] as HttpService,
                            version = "HTTP/2",
                        ),
                    )
                }

                "requestResult" -> {
                    action(arguments[0] as HttpRequest)
                }

                else -> {
                    defaultValue(method.returnType)
                }
            }
        }

    fun request(version: String): HttpRequestToBeSent =
        requestProxy(
            RequestState(
                service = service(arrayOf<Any?>("example.com", 443, true)),
                version = version,
            ),
        ) as HttpRequestToBeSent

    private fun service(arguments: Array<out Any?>): HttpService {
        val host = arguments[0] as String
        val port = arguments[1] as Int
        val secure = arguments[2] as Boolean
        return proxy { method, _ ->
            when (method.name) {
                "host" -> host
                "port" -> port
                "secure" -> secure
                "toString" -> "$host:$port"
                else -> defaultValue(method.returnType)
            }
        }
    }

    private fun requestProxy(state: RequestState): HttpRequest =
        proxy<HttpRequestToBeSent> { method, arguments ->
            when (method.name) {
                "httpService" -> {
                    state.service
                }

                "httpVersion" -> {
                    state.version
                }

                "url" -> {
                    "https://example.com/socket"
                }

                "headers" -> {
                    sourceHeaders
                }

                "body" -> {
                    sourceBody
                }

                "headerValue" -> {
                    state.headers[(arguments[0] as String).lowercase()]
                }

                "withService" -> {
                    state.service = arguments[0] as HttpService
                    requestProxy(state)
                }

                "withHeader" -> {
                    state.headers[(arguments[0] as String).lowercase()] = arguments[1] as String
                    requestProxy(state)
                }

                "withRemovedHeader" -> {
                    state.headers.remove((arguments[0] as String).lowercase())
                    requestProxy(state)
                }

                else -> {
                    defaultValue(method.returnType)
                }
            }
        }

    private fun action(request: HttpRequest): RequestToBeSentAction =
        proxy { method, _ ->
            when (method.name) {
                "request" -> request
                else -> defaultValue(method.returnType)
            }
        }

    private fun header(
        name: String,
        value: String,
    ): HttpHeader =
        proxy { method, _ ->
            when (method.name) {
                "name" -> name
                "value" -> value
                "toString" -> "$name: $value"
                else -> defaultValue(method.returnType)
            }
        }
}

private data class RequestState(
    var service: HttpService,
    val version: String,
    val headers: MutableMap<String, String> = mutableMapOf(),
)

private inline fun <reified T> proxy(crossinline invoke: (Method, Array<out Any?>) -> Any?): T =
    Proxy.newProxyInstance(T::class.java.classLoader, arrayOf(T::class.java)) { _, method, arguments ->
        invoke(method, arguments ?: emptyArray())
    } as T

private fun defaultValue(type: Class<*>): Any? =
    when (type) {
        java.lang.Boolean.TYPE -> false
        java.lang.Byte.TYPE -> 0.toByte()
        java.lang.Short.TYPE -> 0.toShort()
        java.lang.Integer.TYPE -> 0
        java.lang.Long.TYPE -> 0L
        java.lang.Float.TYPE -> 0F
        java.lang.Double.TYPE -> 0.0
        java.lang.Character.TYPE -> '\u0000'
        else -> null
    }
