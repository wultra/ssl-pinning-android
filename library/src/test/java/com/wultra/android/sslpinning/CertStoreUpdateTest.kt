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

        val remoteDataProvider: RemoteDataProvider = mockk()
        every { remoteDataProvider.getFingerprints(any()) } answers {
            RemoteDataResponse(
                200,
                mapOf(CertStore.RESPONSE_SIGNATURE_HEADER to "AAAA"),
                """
                    {
                      "fingerprints": [
                        {
                          "name" : "github.com",
                          "fingerprint" : "kqN/vV4hpTqVxxbhFE9EL1grlND6/Gc+tnF6TrUaiKc=",
                          "expires" : 2212460799,
                          "signature" : "MEUCICB69UpMPOdtrsR6XcJqHEh2L2RO4oSJ3SZ7BYnTBJbGAiEAnZ7rEWdMVGwa59Wx5QbAorEFxXH89Iu0CnqWa96Eda0="
                        }
                      ]
                    }
                """.toByteArray()
            )
        }

        every { cryptoProvider.ecdsaValidateSignature(any(), any()) } returns true

        val updateResult = performForcedUpdate(remoteDataProvider)
        Assert.assertEquals(UpdateResult.OK, updateResult)
    }

    @Test
    @Throws(Exception::class)
    fun testInvalidSignatureUpdate() {

        val remoteDataProvider: RemoteDataProvider = mockk()
        every { remoteDataProvider.getFingerprints(any()) } answers {
            RemoteDataResponse(
                200,
                mapOf(CertStore.RESPONSE_SIGNATURE_HEADER to "AAAA"),
                """
                    { 
                      "fingerprints": [{
                        "name" : "github.com",
                        "fingerprint" : "kqN/vV4hpTqVxxbhFE9EL1grlND6/Gc+tnF6TrUaiKc=",
                        "expires" : 2212460799,
                        "signature" : "MEQCIAiq/O5IbZ8K2SsZtDbpsvHWecxu4eLOSS7oOXjDk2KeAiBKkI53ESVByK+wKwaLA5LsEu8oonUHiYVM2zQtWf46DA=="
                      }]
                    }
                """.toByteArray()
            )
        }

        every { cryptoProvider.ecdsaValidateSignature(any(), any()) } returns false
        val updateResult = performForcedUpdate(remoteDataProvider)
        Assert.assertEquals(UpdateResult.INVALID_SIGNATURE, updateResult)
    }

    @Test
    @Throws(Exception::class)
    fun testExpiredUpdate() {

        val remoteDataProvider: RemoteDataProvider = mockk()
        every { remoteDataProvider.getFingerprints(any()) } answers {
            RemoteDataResponse(
                200,
                mapOf(CertStore.RESPONSE_SIGNATURE_HEADER to "AAAA"),
                """
                    {
                      "fingerprints": [
                        {
                          "name" : "github.com",
                          "fingerprint" : "MRFQDEpmASza4zPsP8ocnd5FyVREDn7kE3Fr/zZjwHQ=",
                          "expires" : 1531185600,
                          "signature" : "MEUCIQD8nGyux9GM8u3XCrRiuJj/N2eEuB0oiHzTEpGyy2gE9gIgYIRfyed6ykDzZbK1ougq1SoRW8UBe5q3VmWihHuL2JY="
                        }
                      ]
                    }
                """.toByteArray()
            )
        }

        every { cryptoProvider.ecdsaValidateSignature(any(), any()) } returns true

        val updateResult = performForcedUpdate(remoteDataProvider)
        Assert.assertEquals(UpdateResult.OK, updateResult)
    }

    @Test
    @Throws(Exception::class)
    fun testUpdateWithNoUpdateObserver() {
        val remoteDataProvider: RemoteDataProvider = mockk()
        val latch = CountDownLatch(1)
        every { remoteDataProvider.getFingerprints(any()) } answers {
            val bytes = """{
              "fingerprints": [
                {
                  "name" : "github.com",
                  "fingerprint" : "trmmrz6GbL4OajB+fdoXOzcrLTrD8GrxX5dxh3OEgAg=",
                  "expires" : 1652184000,
                  "signature" : "MEUCIQCs1y/nyrKh4+2DIuX/PufUYiaVUdt2FBZQg6rBeZ/r4QIgNlT4owBwJ1ThrDsE0SwGipTNI74vP1vNyLNEwuXY4lE="
                }
              ]
            }""".toByteArray()
            latch.countDown()
            RemoteDataResponse(200, mapOf(CertStore.RESPONSE_SIGNATURE_HEADER to "AAAA"), bytes)
        }
        val store = getCertStore(remoteDataProvider)
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

    @Test
    @Throws(Exception::class)
    fun testMissingSignatureHeader() {
        // Arrange: valid response body, but no x-cert-pinning-signature header at all.
        val remoteDataProvider: RemoteDataProvider = mockk()
        every { remoteDataProvider.getFingerprints(any()) } answers {
            RemoteDataResponse(
                200,
                emptyMap(),
                """
                    {
                      "fingerprints": [
                        {
                          "name" : "github.com",
                          "fingerprint" : "kqN/vV4hpTqVxxbhFE9EL1grlND6/Gc+tnF6TrUaiKc=",
                          "expires" : 2212460799,
                          "signature" : "MEUCICB69UpMPOdtrsR6XcJqHEh2L2RO4oSJ3SZ7BYnTBJbGAiEAnZ7rEWdMVGwa59Wx5QbAorEFxXH89Iu0CnqWa96Eda0="
                        }
                      ]
                    }
                """.toByteArray()
            )
        }

        // Act
        val updateResult = performForcedUpdate(remoteDataProvider)

        // Assert: absent header must be treated as an invalid signature — security-critical.
        Assert.assertEquals(UpdateResult.INVALID_SIGNATURE, updateResult)
    }

    @Throws(Exception::class)
    private fun performForcedUpdate(remoteDataProvider: RemoteDataProvider): UpdateResult {
        val store = getCertStore(remoteDataProvider)
        TestUtils.assignHandler(store, handler)
        return TestUtils.updateAndCheck(store, UpdateMode.FORCED, null)
    }

    private fun getCertStore(remoteDataProvider: RemoteDataProvider): CertStore {
        val publicKeyBytes = Base64.getDecoder().decode("BC3kV9OIDnMuVoCdDR9nEA/JidJLTTDLuSA2TSZsGgODSshfbZg31MS90WC/HdbU/A5WL5GmyDkE/iks6INv+XE=")
        val config = TestUtils.getCertStoreConfiguration(
            Date(),
            arrayOf("github.com"),
            URL("https://test"),
            publicKeyBytes,
            null
        )
        return CertStore(config, cryptoProvider, secureDataStore, remoteDataProvider)
    }
}