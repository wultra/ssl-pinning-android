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

import com.wultra.android.sslpinning.model.GetFingerprintResponse
import com.wultra.android.sslpinning.service.RemoteDataProvider
import com.wultra.android.sslpinning.service.RemoteDataResponse
import io.mockk.every
import io.mockk.mockk

import org.junit.Test

import java.net.URL
import java.util.Base64
import java.util.Date
import java.util.concurrent.TimeUnit

import org.junit.Assert.assertEquals

/**
 * Tests for validation with [CertStore].
 *
 * @author Tomas Kypta, tomas.kypta@wultra.com
 */
class CertStoreValidationTest : CommonKotlinTest() {

    @Test
    @Throws(Exception::class)
    fun testValidationGithubFallbackInvalid() {
        val fingerprintBase64 = "trmmrz6GbL4OajB+fdoXOzcrLTrD8GrxX5dxh3OEgAg="
        val expectedResult = ValidationResult.UNTRUSTED
        val publicKey = "BC3kV9OIDnMuVoCdDR9nEA/JidJLTTDLuSA2TSZsGgODSshfbZg31MS90WC/HdbU/A5WL5GmyDkE/iks6INv+XE="
        val publicKeyBytes = Base64.getDecoder().decode(publicKey)

        val signatureBase64 = "MEUCICB69UpMPOdtrsR6XcJqHEh2L2RO4oSJ3SZ7BYnTBJbGAiEAnZ7rEWdMVGwa59Wx5QbAorEFxXH89Iu0CnqWa96Eda0="
        val signatureBytes = Base64.getDecoder().decode(signatureBase64)
        val fingerprintBytes = Base64.getDecoder().decode(fingerprintBase64)

        val fallbackEntry = GetFingerprintResponse.Entry(
            "github.com",
            fingerprintBytes,
            Date(System.currentTimeMillis() + TimeUnit.DAYS.toMillis(1)),
            signatureBytes)
        val fallback = arrayOf(fallbackEntry)

        val config = TestUtils.getCertStoreConfiguration(
            Date(),
            arrayOf("github.com"),
            URL("https://github.com"),
            publicKeyBytes,
            fallback)
        val store = CertStore(config, cryptoProvider, secureDataStore)
        TestUtils.assignHandler(store, handler)
        val result = store.validateCertificate(TestUtils.githubCert())
        assertEquals(expectedResult, result)
    }

    @Test
    @Throws(Exception::class)
    fun testValidationGithubUpdateWithOutdatedData() {

        val remoteDataProvider: RemoteDataProvider = mockk()
        every { remoteDataProvider.getFingerprints(any()) } answers {
            RemoteDataResponse(
                200,
                sigHeader,
                """
                    {
                      "fingerprints": [
                        {
                          "name" : "github.com",
                          "fingerprint" : "trmmrz6GbL4OajB+fdoXOzcrLTrD8GrxX5dxh3OEgAg=",
                          "expires" : 1652184000,
                          "signature" : "MEUCIQCs1y/nyrKh4+2DIuX/PufUYiaVUdt2FBZQg6rBeZ/r4QIgNlT4owBwJ1ThrDsE0SwGipTNI74vP1vNyLNEwuXY4lE="
                        }
                      ]
                    }
                """.toByteArray()
            )
        }
        every { cryptoProvider.ecdsaValidateSignature(any(), any()) } returns true

        // json with outdated data, correct public key
        validateGithubWithUpdateJsonOnly(remoteDataProvider, UpdateResult.OK, ValidationResult.EMPTY)
    }

    @Test
    @Throws(Exception::class)
    fun testValidationGithubUpdateWithInvalidSignature() {

        val remoteDataProvider: RemoteDataProvider = mockk()
        every { remoteDataProvider.getFingerprints(any()) } answers {
            RemoteDataResponse(
                200,
                emptyMap(),
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
        every { cryptoProvider.ecdsaValidateSignature(any(), any()) } returns true

        // json with current data, invalid header signature
        validateGithubWithUpdateJsonOnly(remoteDataProvider, UpdateResult.INVALID_SIGNATURE, ValidationResult.EMPTY)
    }

    @Test
    @Throws(Exception::class)
    fun testValidationGithubUpdateWithValidData() {

        val remoteDataProvider: RemoteDataProvider = mockk()
        every { remoteDataProvider.getFingerprints(any()) } answers {
            RemoteDataResponse(
                200,
                sigHeader,
                TestUtils.validFingerprintJsonResponse()
            )
        }
        every { cryptoProvider.ecdsaValidateSignature(any(), any()) } returns true
        
        // json with current data, correct public key
        validateGithubWithUpdateJsonOnly(remoteDataProvider, UpdateResult.OK, ValidationResult.TRUSTED)
    }

    @Throws(Exception::class)
    fun validateGithubWithUpdateJsonOnly(
        provider: RemoteDataProvider,
        expectedUpdateResult: UpdateResult,
        expectedValidationResult: ValidationResult
    ) {
        val publicKeyBytes = Base64.getDecoder().decode(TestUtils.testPubKey())
        val config = TestUtils.getCertStoreConfiguration(
            Date(),
            arrayOf("github.com"),
            URL("https://test"),
            publicKeyBytes,
            null
        )

        val store = CertStore(config, cryptoProvider, secureDataStore, provider)

        TestUtils.assignHandler(store, handler)
        TestUtils.updateAndCheck(store, UpdateMode.FORCED, expectedUpdateResult)

        val result = store.validateCertificate(TestUtils.githubCert())
        assertEquals(expectedValidationResult, result)
    }
}
