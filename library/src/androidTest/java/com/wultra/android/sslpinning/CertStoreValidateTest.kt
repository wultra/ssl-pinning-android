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
import com.wultra.android.sslpinning.model.GetFingerprintResponse
import com.wultra.android.sslpinning.integration.powerauth.powerAuthCertStore
import org.junit.Assert
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Test [CertStore] validation.
 *
 * @author Tomas Kypta, tomas.kypta@wultra.com
 */
@RunWith(AndroidJUnit4::class)
class CertStoreValidateTest {

    @Test
    fun validateWithFallback() {
        val appContext = InstrumentationRegistry.getTargetContext()

        val fallbackFingerprints = GSON.fromJson(jsonData, GetFingerprintResponse::class.java)
        val config = CertStoreConfiguration.Builder(url, getPublicKeyBytes())
                .fallbackCertificate(fallbackFingerprints.fingerprints[0])
                .build()
        val store = CertStore.powerAuthCertStore(config, appContext)

        val cert = getCertificateFromUrl("https://github.com")
        val result = store.validateCertificate(cert)
        Assert.assertEquals(ValidationResult.TRUSTED, result)
    }

    @Test
    fun validateAfterUpdate() {
        val appContext = InstrumentationRegistry.getTargetContext()

        val config = CertStoreConfiguration.Builder(url, getPublicKeyBytes())
                .build()
        val store = CertStore.powerAuthCertStore(config, appContext)
        val updateResult = store.update(UpdateMode.FORCED)
        Assert.assertEquals(UpdateResult.OK, updateResult)

        val cert = getCertificateFromUrl("https://github.com")
        val result = store.validateCertificate(cert)
        Assert.assertEquals(ValidationResult.TRUSTED, result)
    }
}