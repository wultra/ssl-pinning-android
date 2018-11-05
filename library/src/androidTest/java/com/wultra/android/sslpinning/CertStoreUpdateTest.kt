/*
 * Copyright 2018 Wultra s.r.o.
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

package com.wultra.android.sslpinning

import android.support.test.InstrumentationRegistry
import android.support.test.runner.AndroidJUnit4
import android.util.Base64
import com.wultra.android.sslpinning.powerauth.PowerAuthCryptoProvider
import com.wultra.android.sslpinning.powerauth.PowerAuthSecureDataStore
import com.wultra.android.sslpinning.powerauth.powerAuthCertStore
import com.wultra.android.sslpinning.service.RemoteDataProvider
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import java.net.URL

/**
 * Instrumentation test for signature validation on a device/emulator.
 *
 * @author Tomas Kypta, tomas.kypta@wultra.com
 */
@RunWith(AndroidJUnit4::class)
class CertStoreUpdateTest {

    val remoteDataProvider: RemoteDataProvider = object : RemoteDataProvider  {
        override fun getFingerprints(): kotlin.ByteArray {
            val jsonData =
"""
{
  "fingerprints": [
    {
      "name" : "github.com",
      "fingerprint" : "MRFQDEpmASza4zPsP8ocnd5FyVREDn7kE3Fr/zZjwHQ=",
      "expires" : 1591185600,
      "signature" : "MEUCIQD8nGyux9GM8u3XCrRiuJj/N2eEuB0oiHzTEpGyy2gE9gIgYIRfyed6ykDzZbK1ougq1SoRW8UBe5q3VmWihHuL2JY="
    }
  ]
}
"""
            return jsonData.toByteArray(Charsets.UTF_8)
        }
    }

    val url = URL("https://gist.githubusercontent.com/hvge/7c5a3f9ac50332a52aa974d90ea2408c/raw/c5b021db0fcd40b1262ab513bf375e4641834925/ssl-pinning-signatures.json")
    val publicKey = "BC3kV9OIDnMuVoCdDR9nEA/JidJLTTDLuSA2TSZsGgODSshfbZg31MS90WC/HdbU/A5WL5GmyDkE/iks6INv+XE="
    fun getPublicKeyBytes(): ByteArray {
        return Base64.decode(publicKey, android.util.Base64.NO_WRAP)
    }

    @Test
    fun testLocalUpdateSignatureGithub() {
        val appContext = InstrumentationRegistry.getTargetContext()

        val config = CertStoreConfiguration.Builder(url, getPublicKeyBytes()).build()
        val store = CertStore(config, PowerAuthCryptoProvider(), PowerAuthSecureDataStore(appContext), remoteDataProvider)

        val updateResult = store.update(UpdateMode.FORCED)
        assertEquals(UpdateResult.OK, updateResult)
    }

    @Test
    fun testRemoteUpdateSignatureGithub() {
        val appContext = InstrumentationRegistry.getTargetContext()

        val config = CertStoreConfiguration.Builder(url, getPublicKeyBytes()).build()
        val store = CertStore.powerAuthCertStore(config, appContext)

        val updateResult = store.update(UpdateMode.FORCED)
        assertEquals(UpdateResult.OK, updateResult)
    }

    @Test
    fun testRemoteUpdateSignatureGithub_InvalidSignature() {
        val appContext = InstrumentationRegistry.getTargetContext()

        // intentionally different signature
        val publicKey = "BEG6g28LNWRcmdFzexSNTKPBYZnDtKrCyiExFKbktttfKAF7wG4Cx1Nycr5PwCoICG1dRseLyuDxUilAmppPxAo="
        val publicKeyBytes = Base64.decode(publicKey, android.util.Base64.NO_WRAP)

        val config = CertStoreConfiguration.Builder(url, publicKeyBytes).build()
        val store = CertStore.powerAuthCertStore(config, appContext)

        val updateResult = store.update(UpdateMode.FORCED)
        assertEquals(UpdateResult.INVALID_SIGNATURE, updateResult)
    }
}