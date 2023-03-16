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

import com.wultra.android.sslpinning.TestUtils.assignHandler
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.ArgumentMatchers.anyString
import org.mockito.Mockito.*
import org.powermock.modules.junit4.PowerMockRunner
import java.net.URL
import java.util.*
import org.mockito.Mockito.`when` as wh

/**
 * Test global validation observers.
 *
 * @author Tomas Kypta, tomas.kypta@wultra.com
 */
@RunWith(PowerMockRunner::class)
class ValidationObserverTest : CommonKotlinTest() {

    @Test
    fun testValidationObservers() {
        val cert = TestUtils.getCertificateFromUrl("https://github.com")
        val certGoogle = TestUtils.getCertificateFromUrl("https://google.com")

        val publicKey = "BC3kV9OIDnMuVoCdDR9nEA/JidJLTTDLuSA2TSZsGgODSshfbZg31MS90WC/HdbU/A5WL5GmyDkE/iks6INv+XE="
        val publicKeyBytes = java.util.Base64.getDecoder().decode(publicKey)

        val config = TestUtils.getCertStoreConfiguration(
                Date(),
                arrayOf("github.com"),
                URL("https://gist.githubusercontent.com/hvge/7c5a3f9ac50332a52aa974d90ea2408c/raw/07eb5b4b67e63d37d224912bc5951c7b589b35e6/ssl-pinning-signatures.json"),
                publicKeyBytes,
                null)
        val store = CertStore(config, cryptoProvider, secureDataStore)
        assignHandler(store, handler)

        var observer: ValidationObserver = mock(ValidationObserver::class.java)
        store.addValidationObserver(observer)
        val result = store.validateCertificate(cert)
        assertEquals(ValidationResult.EMPTY, result)
        verify(observer, times(0)).onValidationUntrusted(anyString())
        verify(observer, times(1)).onValidationEmpty(anyString())
        verify(observer, times(0)).onValidationTrusted(anyString())
        store.removeValidationObserver(observer)

        TestUtils.updateAndCheck(store, UpdateMode.FORCED, UpdateResult.OK)

        observer = mock(ValidationObserver::class.java)
        store.addValidationObserver(observer)
        val result2 = store.validateCertificate(cert)
        assertEquals(ValidationResult.TRUSTED, result2)
        verify(observer, times(0)).onValidationUntrusted(anyString())
        verify(observer, times(0)).onValidationEmpty(anyString())
        verify(observer, times(1)).onValidationTrusted(anyString())
        store.removeAllValidationObservers()

        observer = mock(ValidationObserver::class.java)
        store.addValidationObserver(observer)
        val result3 = store.validateCertificate(certGoogle)
        assertEquals(ValidationResult.UNTRUSTED, result3)
        verify(observer, times(1)).onValidationUntrusted(anyString())
        verify(observer, times(0)).onValidationEmpty(anyString())
        verify(observer, times(0)).onValidationTrusted(anyString())
        store.removeAllValidationObservers()
    }
}