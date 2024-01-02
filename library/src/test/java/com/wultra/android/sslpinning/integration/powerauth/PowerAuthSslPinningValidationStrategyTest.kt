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
package com.wultra.android.sslpinning.integration.powerauth

import com.wultra.android.sslpinning.CertStore
import com.wultra.android.sslpinning.CommonKotlinTest
import com.wultra.android.sslpinning.TestUtils
import com.wultra.android.sslpinning.UpdateMode
import com.wultra.android.sslpinning.UpdateResult
import io.getlime.security.powerauth.networking.ssl.HttpClientValidationStrategy
import io.mockk.verify
import org.junit.Assert
import org.junit.Test
import java.net.URL
import java.util.Base64
import java.util.Date
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLHandshakeException

/**
 * Unit test for PowerAuthSslPinningValidationStrategy.
 *
 * @author Tomas Kypta, tomas.kypta@wultra.com
 */
class PowerAuthSslPinningValidationStrategyTest : CommonKotlinTest() {
    @Test
    @Throws(Exception::class)
    fun testPowerAuthSslPinningValidationStrategyOnGithubSuccess() {
        val publicKey =
            "BC3kV9OIDnMuVoCdDR9nEA/JidJLTTDLuSA2TSZsGgODSshfbZg31MS90WC/HdbU/A5WL5GmyDkE/iks6INv+XE="
        val publicKeyBytes = Base64.getDecoder().decode(publicKey)
        val config = TestUtils.getCertStoreConfiguration(
            Date(), arrayOf("github.com"),
            URL("https://gist.githubusercontent.com/hvge/7c5a3f9ac50332a52aa974d90ea2408c/raw/07eb5b4b67e63d37d224912bc5951c7b589b35e6/ssl-pinning-signatures.json"),
            publicKeyBytes,
            null
        )
        val store = CertStore(config, cryptoProvider, secureDataStore)
        TestUtils.assignHandler(store, handler)
        TestUtils.updateAndCheck(store, UpdateMode.FORCED, UpdateResult.OK)
        val strategy: HttpClientValidationStrategy = PowerAuthSslPinningValidationStrategy(store)
        val url = URL("https://github.com")
        val urlConnection = url.openConnection()
        val sslConnection = urlConnection as HttpsURLConnection
        val sslSocketFactory = strategy.sslSocketFactory
        if (sslSocketFactory != null) {
            sslConnection.sslSocketFactory = sslSocketFactory
        }
        val hostnameVerifier = strategy.hostnameVerifier
        if (hostnameVerifier != null) {
            sslConnection.hostnameVerifier = hostnameVerifier
        }
        verify(exactly = 0) { cryptoProvider.hashSha256(any()) }
        sslConnection.connect()
        val response = sslConnection.responseCode
        Assert.assertEquals(2, (response / 100).toLong())
        sslConnection.disconnect()
        verify(exactly = 1) { cryptoProvider.hashSha256(any()) }
        verify { secureDataStore.load(any()) }
    }

    @Test(expected = SSLHandshakeException::class)
    @Throws(Exception::class)
    fun testPowerAuthSslPinningValidationStrategyOnGithubFailure() {
        val publicKey =
            "BC3kV9OIDnMuVoCdDR9nEA/JidJLTTDLuSA2TSZsGgODSshfbZg31MS90WC/HdbU/A5WL5GmyDkE/iks6INv+XE="
        val publicKeyBytes = Base64.getDecoder().decode(publicKey)
        val config = TestUtils.getCertStoreConfiguration(
            Date(), arrayOf("github.com"),
            URL("https://test.wultra.com"),
            publicKeyBytes,
            null
        )
        val store = CertStore(config, cryptoProvider, secureDataStore)
        TestUtils.assignHandler(store, handler)
        val strategy: HttpClientValidationStrategy = PowerAuthSslPinningValidationStrategy(store)
        val url = URL("https://github.com")
        val urlConnection = url.openConnection()
        val sslConnection = urlConnection as HttpsURLConnection
        val sslSocketFactory = strategy.sslSocketFactory
        if (sslSocketFactory != null) {
            sslConnection.sslSocketFactory = sslSocketFactory
        }
        val hostnameVerifier = strategy.hostnameVerifier
        if (hostnameVerifier != null) {
            sslConnection.hostnameVerifier = hostnameVerifier
        }
        verify(exactly = 0) { cryptoProvider.hashSha256(any()) }
        sslConnection.connect()
    }
}