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

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.wultra.android.sslpinning.integration.powerauth.powerAuthCertStore
import com.wultra.android.sslpinning.model.GetFingerprintResponse
import org.junit.Assert
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Test [CertStore] validation.
 *
 * @author Tomas Kypta, tomas.kypta@wultra.com
 */
@RunWith(AndroidJUnit4::class)
class CertStoreValidateTest : CommonTest() {

    @Test
    fun validateWithFallback() {
        val fallbackFingerprints = GSON.fromJson(jsonData, GetFingerprintResponse::class.java)
        val config = CertStoreConfiguration.Builder(url, getPublicKeyBytes())
                .fallbackCertificates(fallbackFingerprints)
                .build()
        val store = CertStore.powerAuthCertStore(config, appContext)

        val cert = getCertificateFromUrl("https://github.com")
        val result = store.validateCertificate(cert)
        Assert.assertEquals(ValidationResult.TRUSTED, result)
    }

    @Test
    fun validateAfterUpdate() {
        val config = CertStoreConfiguration.Builder(url, getPublicKeyBytes())
                .build()
        val store = CertStore.powerAuthCertStore(config, appContext)
        updateAndCheck(store, UpdateMode.FORCED, UpdateResult.OK)

        val cert = getCertificateFromUrl("https://github.com")
        val result = store.validateCertificate(cert)
        Assert.assertEquals(ValidationResult.TRUSTED, result)
    }
}