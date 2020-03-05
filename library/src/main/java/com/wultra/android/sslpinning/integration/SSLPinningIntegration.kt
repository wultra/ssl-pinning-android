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

import android.os.Build
import android.util.Log
import com.wultra.android.sslpinning.CertStore
import java.lang.Exception
import java.net.InetAddress
import java.net.Socket
import java.security.KeyManagementException
import java.security.KeyStore
import java.security.NoSuchAlgorithmException
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
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
            return createSSLPinningSocketFactory(SSLPinningX509TrustManager(certStore))
        }

        /**
         * Creates [SSLSocketFactory] for handling WultraSSLPinning.
         * The factory first tests SSL Pinning then if that is ok fallbacks on standard
         * certificate validation.
         *
         * Note: On devices prior to Android API 21, you'll probably need to use ProviderInstaller.installIfNeeded method
         * to ensure, that the device is capable of TLS 1.2 handling.
         *
         * @param sslPinningTrustManager Trust manager capable of handling WultraSSLPinning
         * that makes basis for the [SSLSocketFactory].
         * @return SSLSocketFactory capable of handling WultraSSLPinning.
         */
        @JvmStatic
        fun createSSLPinningSocketFactory(sslPinningTrustManager: SSLPinningX509TrustManager): SSLSocketFactory {
            // obtain default trust managers
            val originalTrustManagerFactory = TrustManagerFactory.getInstance("X509")
            val keyStore: KeyStore? = null
            originalTrustManagerFactory.init(keyStore)
            val originalTrustManagers = originalTrustManagerFactory.trustManagers

            // use all trust managers after the provided (or our [SSLPinningX509TrustManager])
            val trustSslPinningCerts = arrayOf(sslPinningTrustManager, *originalTrustManagers)
            try {
                if (Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP_MR1) {
                    try {
                        val sc = SSLContext.getInstance(Tls12SocketFactory.TLS12NAME)
                        sc.init(null, trustSslPinningCerts, null)
                        return Tls12SocketFactory(sc.socketFactory)
                    } catch (e: Exception) {
                        Log.e("TLS12Factory", e.message)
                    }
                }

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

private class Tls12SocketFactory(private val base: SSLSocketFactory) : SSLSocketFactory() {

    companion object {
        const val TLS12NAME = "TLSv1.2"
    }

    override fun getDefaultCipherSuites(): Array<String> = base.defaultCipherSuites

    override fun getSupportedCipherSuites(): Array<String> = base.supportedCipherSuites

    override fun createSocket(p0: Socket?, p1: String?, p2: Int, p3: Boolean) = base.createSocket(p0, p1, p2, p3).patch()

    override fun createSocket(p0: String?, p1: Int) = base.createSocket(p0, p1).patch()

    override fun createSocket(p0: String?, p1: Int, p2: InetAddress?, p3: Int) = base.createSocket(p0, p1, p2, p3).patch()

    override fun createSocket(p0: InetAddress?, p1: Int) = base.createSocket(p0, p1).patch()

    override fun createSocket(p0: InetAddress?, p1: Int, p2: InetAddress?, p3: Int) = base.createSocket(p0, p1, p2, p3).patch()

    private fun Socket.patch(): Socket {
        return (this as? SSLSocket)?.apply {
            enabledProtocols += TLS12NAME
        } ?: this
    }
}