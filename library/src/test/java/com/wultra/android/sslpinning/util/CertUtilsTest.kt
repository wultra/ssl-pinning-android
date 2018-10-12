package com.wultra.android.sslpinning.util

import com.wultra.android.sslpinning.TestUtils
import org.junit.Assert.*
import org.junit.Test

/**
 * @author Tomas Kypta, tomas.kypta@wultra.com
 */
class CertUtilsTest {

    @Test
    fun testParseCommonName() {
        val cert = TestUtils.getCertificateFromUrl("https://github.com")
        val cn = CertUtils.parseCommonName(cert)
        assertNotNull(cn)
        assertEquals("github.com", cn)
    }
}