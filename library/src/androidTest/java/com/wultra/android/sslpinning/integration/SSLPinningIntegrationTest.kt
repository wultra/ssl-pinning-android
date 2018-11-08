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

package com.wultra.android.sslpinning.integration

import android.support.test.InstrumentationRegistry
import android.support.test.runner.AndroidJUnit4
import com.wultra.android.sslpinning.*
import com.wultra.android.sslpinning.integration.powerauth.powerAuthCertStore
import okhttp3.OkHttpClient
import okhttp3.Request
import org.junit.Assert
import org.junit.Test
import org.junit.runner.RunWith
import java.net.HttpURLConnection
import java.net.URL
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLHandshakeException

/**
 * Integration tests for [SSLPinningIntegration] and [SSLPinningX509TrustManager].
 *
 * @author Tomas Kypta, tomas.kypta@wultra.com
 */
@RunWith(AndroidJUnit4::class)
class SSLPinningIntegrationTest {

    @Test
    fun testValidationwithHttpsUrlConnection_ValidCert() {
        val appContext = InstrumentationRegistry.getTargetContext()

        val config = CertStoreConfiguration.Builder(url, getPublicKeyBytes())
                .build()
        val store = CertStore.powerAuthCertStore(config, appContext)
        val updateResult = store.update(UpdateMode.FORCED)
        Assert.assertEquals(UpdateResult.OK, updateResult)

        val url = URL("https://github.com")

        val httpURLConnection = url.openConnection() as HttpURLConnection
        val connection = httpURLConnection as HttpsURLConnection

        connection.sslSocketFactory = SSLPinningIntegration.createSSLPinningSocketFactory(store)
        try {
            connection.connect()
        } catch (e: SSLHandshakeException) {
            Assert.fail()
        } finally {
            connection.disconnect()
        }
    }

    @Test(expected = SSLHandshakeException::class)
    fun testValidationwithHttpsUrlConnection_InvalidCert() {
        val appContext = InstrumentationRegistry.getTargetContext()

        val config = CertStoreConfiguration.Builder(url, getPublicKeyBytes())
                .build()
        val store = CertStore.powerAuthCertStore(config, appContext)
        val updateResult = store.update(UpdateMode.FORCED)
        Assert.assertEquals(UpdateResult.OK, updateResult)

        val url = URL("https://google.com")

        val httpURLConnection = url.openConnection() as HttpURLConnection
        val connection = httpURLConnection as HttpsURLConnection

        connection.sslSocketFactory = SSLPinningIntegration.createSSLPinningSocketFactory(store)
        try {
            connection.connect()
            // should not reach here, SSLHandshakeException because validation returns ValidationResult.EMPTY
            Assert.fail()
        } finally {
            connection.disconnect()
        }
    }

    @Test
    fun testValidationwithOkHttp_ValidCert() {
        val appContext = InstrumentationRegistry.getTargetContext()

        val config = CertStoreConfiguration.Builder(url, getPublicKeyBytes())
                .build()
        val store = CertStore.powerAuthCertStore(config, appContext)
        val updateResult = store.update(UpdateMode.FORCED)
        Assert.assertEquals(UpdateResult.OK, updateResult)

        val url = URL("https://github.com")

        val trustManager = SSLPinningX509TrustManager(store)
        val sslSocketFactory = SSLPinningIntegration.createSSLPinningSocketFactory(trustManager)

        val okhttpClient = OkHttpClient.Builder()
                .sslSocketFactory(sslSocketFactory, trustManager)
                .build()

        val request = Request.Builder()
                .url(url)
                .build()

        try {
            okhttpClient.newCall(request).execute()
        } catch (e: SSLHandshakeException) {
            Assert.fail()
        }
    }

    @Test(expected = SSLHandshakeException::class)
    fun testValidationwithOkHttp_InvalidCert() {
        val appContext = InstrumentationRegistry.getTargetContext()

        val config = CertStoreConfiguration.Builder(url, getPublicKeyBytes())
                .build()
        val store = CertStore.powerAuthCertStore(config, appContext)
        val updateResult = store.update(UpdateMode.FORCED)
        Assert.assertEquals(UpdateResult.OK, updateResult)

        val url = URL("https://google.com")

        val trustManager = SSLPinningX509TrustManager(store)
        val sslSocketFactory = SSLPinningIntegration.createSSLPinningSocketFactory(trustManager)

        val okhttpClient = OkHttpClient.Builder()
                .sslSocketFactory(sslSocketFactory, trustManager)
                .build()

        val request = Request.Builder()
                .url(url)
                .build()

        okhttpClient.newCall(request).execute()
        // should not reach here, SSLHandshakeException because validation returns ValidationResult.EMPTY
        Assert.fail()
    }
}