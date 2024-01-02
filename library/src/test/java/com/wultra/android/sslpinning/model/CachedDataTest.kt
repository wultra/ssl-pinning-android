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
import org.junit.After
import org.junit.Assert
import org.junit.Before
import org.junit.Test
import java.util.Date

/**
 *
 */
internal class CachedDataTest {
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
    fun testEntries() {
        // the 1st item has different signature, otherwise the data are the same
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

        val responses = jsonData.map {
            CertStore.GSON.fromJson(it, GetFingerprintResponse::class.java)
        }
        responses.forEach {
            Assert.assertEquals(1, it.fingerprints.size)
        }

        val date = Date()
        val cachedDatas = responses.map {
            val certInfos = it.fingerprints.map { entry -> CertificateInfo(entry) }.toTypedArray()
            Assert.assertEquals(1, certInfos.size)
            CachedData(certInfos, date)
        }

        Assert.assertEquals(2, cachedDatas.size)
        Assert.assertEquals(cachedDatas[0], cachedDatas[1])
    }

}