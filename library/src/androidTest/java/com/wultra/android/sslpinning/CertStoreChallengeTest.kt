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

import android.support.test.runner.AndroidJUnit4
import android.util.Base64
import com.wultra.android.sslpinning.integration.powerauth.powerAuthCertStore
import org.junit.Test
import org.junit.runner.RunWith
import java.net.URL

@RunWith(AndroidJUnit4::class)
class CertStoreChallengeTest: CommonTest() {

    private val baseUrl = "https://mobile-utility-server.herokuapp.com/app"
    private val appName = "rb-ekonto"

    @Test
    fun validateUpdateWithChallenge() {
        val config = CertStoreConfiguration.Builder(getServiceUrl("/init?appName=$appName"), getPublicKeyFromServer())
                .useChallenge(true)
                .build()
        val store = CertStore.powerAuthCertStore(config, appContext)
        updateAndCheck(store, UpdateMode.FORCED, UpdateResult.OK)
    }

    private fun getServiceUrl(relativePath: String): URL {
        return URL("$baseUrl$relativePath")
    }

    private data class PublicKeyResponse(var publicKey: String)

    private fun getPublicKeyFromServer(): ByteArray {
        val url = getServiceUrl("/init/public-key?appName=$appName")
        val responseString = url.readText(Charsets.UTF_8)
        val responseObject = GSON.fromJson(responseString, PublicKeyResponse::class.java)
        return Base64.decode(responseObject.publicKey, Base64.NO_WRAP)
    }
}