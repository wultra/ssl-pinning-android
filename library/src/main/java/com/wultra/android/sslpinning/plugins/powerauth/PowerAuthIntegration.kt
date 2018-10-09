package com.wultra.android.sslpinning.plugins.powerauth

import com.wultra.android.sslpinning.CertStore
import com.wultra.android.sslpinning.CertStoreConfiguration
import com.wultra.android.sslpinning.interfaces.ECPublicKey
import io.getlime.security.powerauth.networking.ssl.PA2ClientValidationStrategy
import java.security.KeyManagementException
import java.security.NoSuchAlgorithmException
import java.security.cert.X509Certificate
import javax.net.ssl.*

/**
 * @author Tomas Kypta, tomas.kypta@wultra.com
 */
fun CertStore.Companion.powerAuthCertStore(configuration: CertStoreConfiguration): CertStore {
    return CertStore(configuration = configuration,
            cryptoProvider = PowerAuthCryptoProvider(),
            secureDataStore = PowerAuthSecureDataStore())
}

class PowerAuthSslPinningValidationStrategy(private val certStore: CertStore) : PA2ClientValidationStrategy {

    private val sslPinningTrustManager = object : X509TrustManager {
        override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {
            TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
        }

        override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {
            TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
        }

        override fun getAcceptedIssuers(): Array<X509Certificate> {
            TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
        }
    }

    private class SslPinningHostNameVerifier(private val delegate: HostnameVerifier) : HostnameVerifier {

        override fun verify(hostname: String?, session: SSLSession?): Boolean {
            if (delegate.verify(hostname, session)) {

            }
            return false
        }
    }

    override fun getHostnameVerifier(): HostnameVerifier? {
        return null
    }

    override fun getSSLSocketFactory(): SSLSocketFactory? {
        val trustSslPinningCerts = arrayOf(sslPinningTrustManager)
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