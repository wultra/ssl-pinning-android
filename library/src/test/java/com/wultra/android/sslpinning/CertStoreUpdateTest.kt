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

import com.wultra.android.sslpinning.integration.DefaultUpdateObserver
import com.wultra.android.sslpinning.service.RemoteDataProvider
import com.wultra.android.sslpinning.service.RemoteDataResponse
import io.mockk.every
import io.mockk.mockk
import org.junit.Assert
import org.junit.Test
import java.net.URL
import java.util.Base64
import java.util.Date
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * Unit tests for [CertStore] updates.
 *
 * @author Tomas Kypta, tomas.kypta@wultra.com
 */
class CertStoreUpdateTest : CommonKotlinTest() {

    @Test
    @Throws(Exception::class)
    fun testCorrectUpdate() {
        every { cryptoProvider.ecdsaValidateSignature(any(), any()) } returns true

        val publicKey =
            "BC3kV9OIDnMuVoCdDR9nEA/JidJLTTDLuSA2TSZsGgODSshfbZg31MS90WC/HdbU/A5WL5GmyDkE/iks6INv+XE="
        val pinningJsonUrl =
            "https://gist.githubusercontent.com/hvge/7c5a3f9ac50332a52aa974d90ea2408c/raw/07eb5b4b67e63d37d224912bc5951c7b589b35e6/ssl-pinning-signatures.json"
        val updateResult = performForcedUpdate(publicKey, pinningJsonUrl)
        Assert.assertEquals(UpdateResult.OK, updateResult)
    }

    @Test
    @Throws(Exception::class)
    fun testInvalidSignatureUpdate() {
        every { cryptoProvider.ecdsaValidateSignature(any(), any()) } returns false

        val publicKey =
            "BC3kV9OIDnMuVoCdDR9nEA/JidJLTTDLuSA2TSZsGgODSshfbZg31MS90WC/HdbU/A5WL5GmyDkE/iks6INv+XE="
        val pinningJsonUrl =
            "https://gist.githubusercontent.com/TomasKypta/40be50cc63d2f4c00abcbbf4554f0e32/raw/9cc9029d9e8248b0cd9a36b98382040114dd1d4a/ssl-pinning-signatures_Mar2023.json"
        val updateResult = performForcedUpdate(publicKey, pinningJsonUrl)
        Assert.assertEquals(UpdateResult.INVALID_SIGNATURE, updateResult)
    }

    @Test
    @Throws(Exception::class)
    fun testExpiredUpdate() {
        every { cryptoProvider.ecdsaValidateSignature(any(), any()) } returns false

        val publicKey =
            "BC3kV9OIDnMuVoCdDR9nEA/JidJLTTDLuSA2TSZsGgODSshfbZg31MS90WC/HdbU/A5WL5GmyDkE/iks6INv+XE="
        val pinningJsonUrl =
            "https://gist.githubusercontent.com/TomasKypta/5a6d99fe441a8c0d201b673d88e223a6/raw/0d12746cad1247ebf9a5b1706afabf8486a7a62e/ssl-pinning-signatures_expired.json"
        val updateResult = performForcedUpdate(publicKey, pinningJsonUrl)
        Assert.assertEquals(UpdateResult.STORE_IS_EMPTY, updateResult)
    }

    @Test
    @Throws(Exception::class)
    fun testUpdateSignatureGithub() {
        val publicKey =
            "BC3kV9OIDnMuVoCdDR9nEA/JidJLTTDLuSA2TSZsGgODSshfbZg31MS90WC/HdbU/A5WL5GmyDkE/iks6INv+XE="
        val publicKeyBytes = Base64.getDecoder().decode(publicKey)
        val config = TestUtils.getCertStoreConfiguration(
            Date(), arrayOf("github.com"),
            URL("https://gist.githubusercontent.com/"),
            publicKeyBytes,
            null
        )
        val remoteDataProvider: RemoteDataProvider = mockk()
        val jsonData = """{
  "fingerprints": [
    {
      "name" : "github.com",
      "fingerprint" : "kqN/vV4hpTqVxxbhFE9EL1grlND6/Gc+tnF6TrUaiKc=",
      "expires" : 1710460799,
      "signature" : "MEUCICB69UpMPOdtrsR6XcJqHEh2L2RO4oSJ3SZ7BYnTBJbGAiEAnZ7rEWdMVGwa59Wx5QbAorEFxXH89Iu0CnqWa96Eda0="
    }
  ]
}"""
        every { remoteDataProvider.getFingerprints(any()) } answers {
            RemoteDataResponse(200, emptyMap(), jsonData.toByteArray())
        }
        val store = CertStore(config, cryptoProvider, secureDataStore, remoteDataProvider)
        TestUtils.assignHandler(store, handler)
        TestUtils.updateAndCheck(store, UpdateMode.FORCED, UpdateResult.OK)
    }

    @Test
    @Throws(Exception::class)
    fun testUpdateWithNoUpdateObserver() {
        val publicKey =
            "BC3kV9OIDnMuVoCdDR9nEA/JidJLTTDLuSA2TSZsGgODSshfbZg31MS90WC/HdbU/A5WL5GmyDkE/iks6INv+XE="
        val publicKeyBytes = Base64.getDecoder().decode(publicKey)
        val config = TestUtils.getCertStoreConfiguration(
            Date(), arrayOf("github.com"),
            URL("https://gist.githubusercontent.com/hvge/7c5a3f9ac50332a52aa974d90ea2408c/raw/c5b021db0fcd40b1262ab513bf375e4641834925/ssl-pinning-signatures.json"),
            publicKeyBytes,
            null
        )
        val remoteDataProvider: RemoteDataProvider = mockk()
        val jsonData = """{
  "fingerprints": [
    {
      "name" : "github.com",
      "fingerprint" : "trmmrz6GbL4OajB+fdoXOzcrLTrD8GrxX5dxh3OEgAg=",
      "expires" : 1652184000,
      "signature" : "MEUCIQCs1y/nyrKh4+2DIuX/PufUYiaVUdt2FBZQg6rBeZ/r4QIgNlT4owBwJ1ThrDsE0SwGipTNI74vP1vNyLNEwuXY4lE="
    }
  ]
}"""
        val latch = CountDownLatch(1)
        every { remoteDataProvider.getFingerprints(any()) } answers {
            val bytes = jsonData.toByteArray()
            latch.countDown()
            RemoteDataResponse(200, emptyMap(), bytes)
        }
        val store = CertStore(config, cryptoProvider, secureDataStore, remoteDataProvider)
        TestUtils.assignHandler(store, handler)
        store.update(UpdateMode.FORCED, object : DefaultUpdateObserver() {
            override fun onUpdateStarted(type: UpdateType) {
                Assert.assertEquals(UpdateType.DIRECT, type)
                super.onUpdateStarted(type)
            }

            override fun onUpdateFinished(type: UpdateType, result: UpdateResult) {
                Assert.assertEquals(UpdateType.DIRECT, type)
                super.onUpdateFinished(type, result)
            }

            override fun handleFailedUpdate(type: UpdateType, result: UpdateResult) {
                Assert.fail()
            }

            override fun continueExecution() {}
        })
        Assert.assertTrue(latch.await(2, TimeUnit.SECONDS))
    }

    @Throws(Exception::class)
    private fun performForcedUpdate(
        publicKey: String,
        pinningJsonUrl: String
    ): UpdateResult {
        val publicKeyBytes = Base64.getDecoder().decode(publicKey)
        val config = TestUtils.getCertStoreConfiguration(
            Date(), arrayOf("github.com"),
            URL(pinningJsonUrl),
            publicKeyBytes,
            null
        )
        val store = CertStore(config, cryptoProvider, secureDataStore)
        TestUtils.assignHandler(store, handler)
        return TestUtils.updateAndCheck(store, UpdateMode.FORCED, null)
    }
}