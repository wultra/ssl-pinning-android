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

package com.wultra.android.sslpinning.plugins.powerauth

import com.wultra.android.sslpinning.CertStore
import com.wultra.android.sslpinning.ValidationResult
import io.getlime.security.powerauth.networking.ssl.PA2ClientValidationStrategy
import java.security.KeyManagementException
import java.security.KeyStore
import java.security.NoSuchAlgorithmException
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import javax.net.ssl.*

/**
 * Validation strategy for PowerAuth SDK incorporating WultraSSLPinning.
 *
 * It adds extra [X509TrustManager] to the SSLContext in front of the default trust managers.
 * This way first WultraSSLPinning is checked. Then the standard certificate validation
 * has its way.
 */
class PowerAuthSslPinningValidationStrategy(private val certStore: CertStore) : PA2ClientValidationStrategy {

    private val sslPinningTrustManager = object : X509TrustManager {
        override fun checkClientTrusted(chain: Array<out X509Certificate>, authType: String) {
        }

        override fun checkServerTrusted(chain: Array<out X509Certificate>, authType: String) {
            if (certStore.validateCertificate(chain[0]) != ValidationResult.TRUSTED) {
                // reject
                throw CertificateException("WultraSSLpinning doesn't trust the server certificate");
            }
        }

        override fun getAcceptedIssuers(): Array<X509Certificate> {
            return arrayOf()
        }
    }

    override fun getHostnameVerifier(): HostnameVerifier? {
        return null
    }

    override fun getSSLSocketFactory(): SSLSocketFactory? {
        // obtain default trust managers
        val originalTrustManagerFactory = TrustManagerFactory.getInstance("X509");
        originalTrustManagerFactory.init(null as? KeyStore);
        val originalTrustManagers = originalTrustManagerFactory.trustManagers;

        // use all trust managers - the first to run it WultraSSLPinning, then the rest
        val trustSslPinningCerts = arrayOf(sslPinningTrustManager, *originalTrustManagers)
        try {
            val sc = SSLContext.getInstance("TLS")
            sc.init(null, trustSslPinningCerts, null)
            return sc.socketFactory
        } catch (e: NoSuchAlgorithmException) {
            throw RuntimeException(e)
        } catch (e: KeyManagementException) {
            throw RuntimeException(e)
        }

    }
}