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

import com.wultra.android.sslpinning.TestUtils.Companion.assignHandler
import com.wultra.android.sslpinning.service.RemoteDataProvider
import com.wultra.android.sslpinning.service.RemoteDataResponse
import io.mockk.every
import io.mockk.just
import io.mockk.mockk
import io.mockk.runs
import io.mockk.verify
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import java.net.URL
import java.util.*

/**
 * Test global validation observers.
 *
 * @author Tomas Kypta, tomas.kypta@wultra.com
 */
class ValidationObserverTest : CommonKotlinTest() {

    @Test
    fun testValidationObservers() {

        val cert = TestUtils.githubCert()
        val certGoogle = TestUtils.getCertificateFromUrl("https://google.com")

        val publicKeyBytes = Base64.getDecoder().decode(TestUtils.testPubKey())

        val remoteDataProvider: RemoteDataProvider = mockk()
        every { remoteDataProvider.getFingerprints(any()) } answers {
            RemoteDataResponse(
                200,
                sigHeader,
                TestUtils.validFingerprintJsonResponse()
            )
        }

        val config = TestUtils.getCertStoreConfiguration(
                Date(),
                arrayOf("github.com"),
                URL("https://test"),
                publicKeyBytes,
                null
        )

        val store = CertStore(config, cryptoProvider, secureDataStore, remoteDataProvider)
        assignHandler(store, handler)

        var observer: ValidationObserver = mockkValidationObserver()
        store.addValidationObserver(observer)
        val result = store.validateCertificate(cert)
        assertEquals(ValidationResult.EMPTY, result)
        verify(exactly = 0) {
            observer.onValidationUntrusted(any())
            observer.onValidationTrusted(any())
        }
        verify(exactly = 1) {
            observer.onValidationEmpty(any())
        }
        store.removeValidationObserver(observer)

        every { cryptoProvider.ecdsaValidateSignature(any(), any()) } returns true
        TestUtils.updateAndCheck(store, UpdateMode.FORCED, UpdateResult.OK)

        observer = mockkValidationObserver()
        store.addValidationObserver(observer)
        val result2 = store.validateCertificate(cert)
        assertEquals(ValidationResult.TRUSTED, result2)
        verify(exactly = 0) {
            observer.onValidationUntrusted(any())
            observer.onValidationEmpty(any())
        }
        verify(exactly = 1) {
            observer.onValidationTrusted(any())
        }
        store.removeAllValidationObservers()

        observer = mockkValidationObserver()
        store.addValidationObserver(observer)
        val result3 = store.validateCertificate(certGoogle)
        assertEquals(ValidationResult.UNTRUSTED, result3)
        verify(exactly = 0) {
            observer.onValidationEmpty(any())
            observer.onValidationTrusted(any())
        }
        verify(exactly = 1) {
            observer.onValidationUntrusted(any())
        }
        store.removeAllValidationObservers()
    }

    private fun mockkValidationObserver(): ValidationObserver {
        val observer: ValidationObserver = mockk()
        every { observer.onValidationEmpty(any()) } just runs
        every { observer.onValidationTrusted(any()) } just runs
        every { observer.onValidationUntrusted(any()) } just runs
        return observer
    }
}