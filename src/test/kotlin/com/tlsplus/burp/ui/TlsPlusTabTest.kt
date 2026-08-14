package com.tlsplus.burp.ui

import kotlin.test.Test
import kotlin.test.assertEquals

class TlsPlusTabTest {
    @Test
    fun outbound_test_uses_the_tls_diagnostic_endpoint() {
        assertEquals("https://tls.peet.ws/api/all", OUTBOUND_TEST_URL)
    }

    @Test
    fun outbound_test_does_not_override_profile_headers() {
        assertEquals(emptyList(), OUTBOUND_TEST_HEADERS)
    }
}
