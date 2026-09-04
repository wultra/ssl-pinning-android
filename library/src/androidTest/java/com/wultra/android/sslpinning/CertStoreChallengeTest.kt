/*
 * Copyright 2020 Wultra s.r.o.
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
import com.wultra.android.sslpinning.integration.DefaultCryptoProvider
import com.wultra.android.sslpinning.integration.DefaultSecureDataStore
import org.junit.Test
import org.junit.runner.RunWith
import java.util.UUID

@RunWith(AndroidJUnit4::class)
class CertStoreChallengeTest: CommonTest() {

    private lateinit var certStores: Array<CertStore>

    override fun setUp() {
        super.setUp()
        val config = CertStoreConfiguration.Builder(serviceUrl, pubKey).build()
        certStores = arrayOf(
            CertStore(config, DefaultCryptoProvider(), DefaultSecureDataStore(appContext, UUID.randomUUID().toString()))
        )
    }

    @Test
    fun validateUpdateWithChallenge() {
        certStores.forEach { store ->
            updateAndCheck(store, UpdateMode.FORCED, UpdateResult.OK)
        }
    }
}