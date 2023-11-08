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

import android.annotation.SuppressLint
import java.security.KeyManagementException
import java.security.NoSuchAlgorithmException
import java.security.cert.X509Certificate
import javax.net.ssl.*

/**
 * Provides validation strategy how HTTPS requests initiated from this library should be handled.
 */
abstract class SslValidationStrategy {

    companion object {
        /**
         * All secure connections will be trusted.
         *
         * Be aware, that using this option will lead to use an unsafe implementation of `HostnameVerifier`
         * and `X509TrustManager` SSL client validation. This is useful for debug/testing purposes only, e.g.
         * when untrusted self-signed SSL certificate is used on server side.
         *
         * It's strictly recommended to use this option only in debug flavours of your application.
         * Deploying to production may cause "Security alert" in Google Developer Console. Please see
         * [this](https://support.google.com/faqs/answer/7188426) and
         * [this](https://support.google.com/faqs/answer/6346016) Google Help Center articles for more details.
         * Beginning 1 March 2017, Google Play will block publishing of any new apps or updates that use such
         * unsafe implementation of `HostnameVerifier`.
         *
         * How to solve this problem for debug/production flavours in gradle build script:
         *
         * 1. Define boolean type `buildConfigField` in flavour configuration.
         *    ```
         *    productFlavors {
         *      production {
         *        buildConfigField 'boolean', 'TRUST_ALL_SSL_HOSTS', 'false'
         *      }
         *      debug {
         *        buildConfigField 'boolean', 'TRUST_ALL_SSL_HOSTS', 'true'
         *      }
         *    }
         *    ```
         *
         * 2. In code use this conditional initialization for [CertStoreConfiguration.Builder]:
         *    ```kotlin
         *    val publicKey = Base64.decode("BMne....kdh2ak=", Base64.NO_WRAP)
         *    val builder = CertStoreConfiguration.Builder(
         *                     serviceUrl = URL("https://localhost/..."),
         *                     publicKey = publicKey)
         *    if (BuildConfig.TRUST_ALL_SSL_HOSTS) {
         *        builder.sslValidationStrategy(SslValidationStrategy.noValidation())
         *    }
         *    val configuration = builder.build()
         *    ```
         *
         * 3. Set `minifyEnabled` to `true` for release buildType to enable code shrinking with ProGuard.
         */
        @JvmStatic
        fun noValidation(): SslValidationStrategy = NoSslValidationStrategy()
    }

    internal abstract fun sslSocketFactory(): SSLSocketFactory?
    internal abstract fun hostnameVerifier(): HostnameVerifier?
}

/**
 * Implements SSL validation strategy that trust any server certificate.
 * See [SslValidationStrategy.noValidation] for more details.
 */
@Suppress("CustomX509TrustManager")
internal class NoSslValidationStrategy: SslValidationStrategy() {
    override fun sslSocketFactory(): SSLSocketFactory? {
        val trustAllCerts = Array(1) { object : X509TrustManager {
            @SuppressLint("TrustAllX509TrustManager")
            override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {
                // Empty
            }

            @SuppressLint("TrustAllX509TrustManager")
            override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {
                // Empty
            }

            override fun getAcceptedIssuers(): Array<X509Certificate> {
                return emptyArray()
            }
        }}
        return try {
            val context = SSLContext.getInstance("TLS")
            context.init(null, trustAllCerts, null)
            context.socketFactory
        } catch (e: NoSuchAlgorithmException) {
            null
        } catch (e: KeyManagementException) {
            null
        }
    }
    override fun hostnameVerifier(): HostnameVerifier? {
        return HostnameVerifier { _, _ -> true }
    }
}