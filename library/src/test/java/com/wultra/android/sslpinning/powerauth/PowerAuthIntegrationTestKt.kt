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

package com.wultra.android.sslpinning.powerauth

import android.content.Context
import com.wultra.android.sslpinning.CertStore
import com.wultra.android.sslpinning.CertStoreConfiguration
import org.junit.Assert
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.Mock
import org.mockito.junit.MockitoJUnitRunner
import java.net.URL

/**
 * Testing format of Java compatible APIs from Kotlin.
 *
 * @author Tomas Kypta, tomas.kypta@wultra.com
 */
@RunWith(MockitoJUnitRunner::class)
class PowerAuthIntegrationTestKt {

    @Mock
    internal lateinit var context: Context

    @Test
    fun testApis() {
        val url = URL("https://gist.githubusercontent.com/hvge/7c5a3f9ac50332a52aa974d90ea2408c/raw/c5b021db0fcd40b1262ab513bf375e4641834925/ssl-pinning-signatures.json")
        val publicKey = "BC3kV9OIDnMuVoCdDR9nEA/JidJLTTDLuSA2TSZsGgODSshfbZg31MS90WC/HdbU/A5WL5GmyDkE/iks6INv+XE="
        val publicKeyBytes = java.util.Base64.getDecoder().decode(publicKey)

        val configuration = CertStoreConfiguration.Builder(url, publicKeyBytes)
                .build()
        val store1 = PowerAuthCertStore.createInstance(configuration, context, null)
        Assert.assertNotNull(store1)
        val store2 = PowerAuthCertStore.createInstance(configuration, context)
        Assert.assertNotNull(store2)

        // Kotlin API
        val store3 = CertStore.powerAuthCertStore(configuration, context, "")
        Assert.assertNotNull(store3)
    }
}