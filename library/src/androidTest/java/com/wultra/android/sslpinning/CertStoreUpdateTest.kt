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

import android.support.test.runner.AndroidJUnit4
import android.util.Base64
import com.wultra.android.sslpinning.integration.powerauth.PowerAuthCryptoProvider
import com.wultra.android.sslpinning.integration.powerauth.PowerAuthSecureDataStore
import com.wultra.android.sslpinning.integration.powerauth.powerAuthCertStore
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Instrumentation test for update signature validation on a device/emulator.
 *
 * @author Tomas Kypta, tomas.kypta@wultra.com
 */
@RunWith(AndroidJUnit4::class)
class CertStoreUpdateTest : CommonTest() {

    @Test
    fun testLocalUpdateSignatureGithub() {
        val config = CertStoreConfiguration.Builder(url, getPublicKeyBytes()).build()
        val store = CertStore(config, PowerAuthCryptoProvider(), PowerAuthSecureDataStore(appContext), remoteDataProvider)

        updateAndCheck(store, UpdateMode.FORCED, UpdateResult.OK)
    }

    @Test
    fun testRemoteUpdateSignatureGithub() {
        val config = CertStoreConfiguration.Builder(url, getPublicKeyBytes()).build()
        val store = CertStore.powerAuthCertStore(config, appContext)

        updateAndCheck(store, UpdateMode.FORCED, UpdateResult.OK, UpdateType.DIRECT)
    }

    @Test
    fun testRemoteUpdateSignatureGithubDefault() {
        val config = CertStoreConfiguration.Builder(url, getPublicKeyBytes()).build()
        val store = CertStore.powerAuthCertStore(config, appContext)

        updateAndCheck(store, UpdateMode.DEFAULT, UpdateResult.OK, UpdateType.DIRECT)

        updateAndCheck(store, UpdateMode.DEFAULT, UpdateResult.OK, UpdateType.NO_UPDATE)
    }

    @Test
    fun testRemoteUpdateSignatureGithub_InvalidSignature() {
        // intentionally different signature
        val publicKey = "BEG6g28LNWRcmdFzexSNTKPBYZnDtKrCyiExFKbktttfKAF7wG4Cx1Nycr5PwCoICG1dRseLyuDxUilAmppPxAo="
        val publicKeyBytes = Base64.decode(publicKey, android.util.Base64.NO_WRAP)

        val config = CertStoreConfiguration.Builder(url, publicKeyBytes).build()
        val store = CertStore.powerAuthCertStore(config, appContext)

        updateAndCheck(store, UpdateMode.FORCED, UpdateResult.INVALID_SIGNATURE)
    }
}