package com.tlsplus.burp.core

import kotlin.test.Test
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class TlsPlusCoreTest {
    @Test
    fun start_server_returns_the_os_assigned_endpoint() {
        val core = TlsPlusCore()
        val result = core.startServer("127.0.0.1:0")

        try {
            val status = assertNotNull(result.status)
            assertTrue(status.`running`, result.output)
            val endpoint = assertNotNull(status.`listenAddr`)
            assertNotEquals(0, endpoint.substringAfterLast(':').toInt())
        } finally {
            core.stopServer()
        }
    }
}
