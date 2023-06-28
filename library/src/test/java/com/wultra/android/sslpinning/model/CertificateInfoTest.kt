/*
 * Copyright 2023 Wultra s.r.o.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 */

package com.wultra.android.sslpinning.model

import android.util.Base64
import com.wultra.android.sslpinning.CertStore
import io.mockk.every
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import junit.framework.TestCase.assertTrue
import org.junit.After
import org.junit.Assert
import org.junit.Before
import org.junit.Test


/**
 *
 */
internal class CertificateInfoTest {

    @Before
    fun setUp() {
        mockkStatic(Base64::class)
        every { Base64.decode(any<String>(), any()) } answers {
            java.util.Base64.getDecoder().decode(it.invocation.args[0] as String)
        }
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    @Test
    fun testIndexOf() {
        val certList = mutableListOf<CertificateInfo>()

        // different signatures of the same fingerprints
        // simulates updates with different data
        val jsonData = listOf("""{"fingerprints": [
                      {
                      "name" : "github.com",
                      "fingerprint" : "kqN/vV4hpTqVxxbhFE9EL1grlND6/Gc+tnF6TrUaiKc=",
                      "expires" : 1710460799,
                      "signature" : "MEQCIElYrNRc/RnIJTFM9Or90Op+5YfEc+OA0JCOzEdewx07AiAm/xAKMkhu9k9mXNFNyUSB/A1FbnqKEegpEpsugY5Z/Q=="
                    }
                  ]}""", """{"fingerprints": [
                      {
                      "name" : "github.com",
                      "fingerprint" : "kqN/vV4hpTqVxxbhFE9EL1grlND6/Gc+tnF6TrUaiKc=",
                      "expires" : 1710460799,
                      "signature" : "MEUCIQDGSbss+QVvF5juP3y7/DkUPYIWopabdHrZETGqYMctLgIgX7aKQ8+22AIlmuWczXZKze4w20ycsKzaps4reobjikA="
                    }
                  ]}""")

        // we add the first one
        val response = CertStore.GSON.fromJson(jsonData[0], GetFingerprintResponse::class.java)
        Assert.assertEquals(1, response.fingerprints.size)
        for (entry in response.fingerprints) {
            certList.add(CertificateInfo(entry))
        }

        for (json in jsonData) {
            val resp = CertStore.GSON.fromJson(json, GetFingerprintResponse::class.java)
            Assert.assertEquals(1, resp.fingerprints.size)
            val ci = CertificateInfo(resp.fingerprints[0])
            // the data should pre already present
            val idx = certList.indexOf(ci)
            assertTrue(idx != -1)
            assertTrue(certList.contains(ci))
        }
    }
}