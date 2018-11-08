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

import com.wultra.android.sslpinning.CertStore
import java.security.KeyManagementException
import java.security.KeyStore
import java.security.NoSuchAlgorithmException
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManagerFactory

/**
 * Integration class for creating [SSLSocketFactory] for handling WultraSSLPinning.
 *
 * @author Tomas Kypta, tomas.kypta@wultra.com
 */
class SSLPinningIntegration {

    companion object {

        /**
         * Creates [SSLSocketFactory] for handling WultraSSLPinning.
         * The factory first tests SSL Pinning then if that is ok fallbacks on standard
         * certificate validation.
         *
         * @param certStore CertStore to base the SSL pinning on.
         * @return SSLSocketFactory capable of handling WultraSSLPinning.
         */
        @JvmStatic
        fun createSSLPinningSocketFactory(certStore: CertStore): SSLSocketFactory {
            // obtain default trust managers
            val originalTrustManagerFactory = TrustManagerFactory.getInstance("X509");
            val keyStore: KeyStore? = null
            originalTrustManagerFactory.init(keyStore);
            val originalTrustManagers = originalTrustManagerFactory.trustManagers;

            val trustManager = SSLPinningX509TrustManager(certStore)

            // use all trust managers after the provided (or our [SSLPinningX509TrustManager])
            val trustSslPinningCerts = arrayOf(trustManager, *originalTrustManagers)
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

        /**
         * Creates [SSLSocketFactory] for handling WultraSSLPinning.
         * The factory first tests SSL Pinning then if that is ok fallbacks on standard
         * certificate validation.
         *
         * @param sslPinningTrustManager Trust manager capable of handling WultraSSLPinning
         * that makes basis for the [SSLSocketFactory].
         * @return SSLSocketFactory capable of handling WultraSSLPinning.
         */
        @JvmStatic
        fun createSSLPinningSocketFactory(sslPinningTrustManager: SSLPinningX509TrustManager): SSLSocketFactory {
            // obtain default trust managers
            val originalTrustManagerFactory = TrustManagerFactory.getInstance("X509");
            val keyStore: KeyStore? = null
            originalTrustManagerFactory.init(keyStore);
            val originalTrustManagers = originalTrustManagerFactory.trustManagers;

            // use all trust managers after the provided (or our [SSLPinningX509TrustManager])
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
}