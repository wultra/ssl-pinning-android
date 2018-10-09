package com.wultra.android.sslpinning

import com.google.gson.Gson
import com.google.gson.GsonBuilder
import com.wultra.android.sslpinning.interfaces.CryptoProvider
import com.wultra.android.sslpinning.interfaces.SecureDataStore
import com.wultra.android.sslpinning.model.CachedData
import com.wultra.android.sslpinning.model.CertificateInfo
import com.wultra.android.sslpinning.model.GetFingerprintResponse
import com.wultra.android.sslpinning.service.RemoteDataProvider
import com.wultra.android.sslpinning.service.RestApi
import com.wultra.android.sslpinning.util.ByteArrayTypeAdapter
import java.security.cert.X509Certificate

/**
 * The main class that provides features of the dynamic SSL pinng library.
 *
 * @author Tomas Kypta, tomas.kypta@wultra.com
 */
class CertStore internal constructor(private val configuration: CertStoreConfiguration,
                                     private val cryptoProvider: CryptoProvider,
                                     private val secureDataStore: SecureDataStore,
                                     remoteDataProvider: RemoteDataProvider?) {

    private val remoteDataProvider: RemoteDataProvider


    @Volatile
    private var cacheIsLoaded = false
    private var cachedData: CachedData? = null
    private var fallbackCertificate: CertificateInfo? = null

    companion object {

    }

    init {
        configuration.validate(cryptoProvider)
        if (remoteDataProvider != null) {
            this.remoteDataProvider = remoteDataProvider!!
        } else {
            this.remoteDataProvider = RestApi(baseUrl = configuration.serviceUrl)
        }
    }

    constructor(configuration: CertStoreConfiguration,
                cryptoProvider: CryptoProvider,
                secureDataStore: SecureDataStore) : this(configuration, cryptoProvider, secureDataStore, null) {
    }

    val instanceIdentifier: String
        get() {
            return configuration.identifier ?: "default"
        }

    @Synchronized
    fun reset() {
        cachedData = null
        secureDataStore.remove(key = instanceIdentifier)
    }

    /**
     * Internal function returns array of [CertificateInfo] objects.
     * The array contains the fallback certificate, if provided, at the last position.
     * The operation is thread safe.
     */
    @Synchronized
    internal fun getCertificates(): Array<CertificateInfo> {
        restoreCache()
        var result = cachedData?.certificates ?: arrayOf<CertificateInfo>()
        fallbackCertificate?.let {
            result = arrayOf(*result, it)
        }
        return result
    }

    /**
     * Internal function returns whole `CachedData` structure.
     * The operation is thread safe.
     */
    @Synchronized
    internal fun getCachedData(): CachedData? {
        restoreCache()
        return cachedData
    }

    @Synchronized
    internal fun updateCachedData(update: (CachedData?) -> CachedData?) {
        restoreCache()

        val newData = update(cachedData)
        if (newData != null) {
            cachedData = newData
            saveDataToCache(newData)
        }
    }

    private fun restoreCache() {
        if (!cacheIsLoaded) {
            cachedData = loadCachedData()
            fallbackCertificate = loadFallbackCertificate()
            cacheIsLoaded = true
        }
    }

    internal fun loadCachedData(): CachedData? {
        val encodedData = secureDataStore.load(key = instanceIdentifier) ?: return null
        val cachedData = try {
            getGson().fromJson(String(encodedData), CachedData::class.java)
        } catch (t: Throwable) {
            return null
        }
        return cachedData
    }

    internal fun saveDataToCache(data: CachedData) {
        val encodedData = getGson().toJson(data).toByteArray(Charsets.UTF_8)
        secureDataStore.save(data = encodedData, key = instanceIdentifier)
    }

    internal fun loadFallbackCertificate(): CertificateInfo? {
        val fallbackData = configuration.fallbackCertificateData ?: return null
        val fallbackEntry = try {
            getGson().fromJson(String(fallbackData), GetFingerprintResponse.Entry::class.java)
                    ?: return null
        } catch (t: Throwable) {
            return null
        }
        return CertificateInfo(fallbackEntry)
    }

    fun getGson(): Gson {
        return GsonBuilder()
                .registerTypeAdapter(ByteArray::class.java, ByteArrayTypeAdapter::class.java)
                .create()
    }

    /**
     * Validates whether provided certificate fingerprint is valid for given common name.
     *
     * @param commonName A common name from server's certificate
     * @param fingerprint A SHA-256 fingerprint calculated from certificate's data
     *
     * @return validation result
     */
    fun validateFingerprint(commonName: String, fingerprint: ByteArray): ValidationResult {
        val expected = configuration.expectedCommonNames
        if (expected != null && !expected.contains(commonName)) {
            return ValidationResult.UNTRUSTED
        }

        val certificates = getCertificates()
        if (certificates.isEmpty()) {
            return ValidationResult.EMPTY
        }

        var matchAttempts = 0
        for (info in certificates) {
            if (info.commonName == commonName) {
                if (info.fingerprint == fingerprint) {
                    return ValidationResult.TRUSTED
                }
                matchAttempts += 1
            }
        }

        return if (matchAttempts > 0) {
            ValidationResult.UNTRUSTED
        } else {
            ValidationResult.EMPTY
        }
    }

    fun validateCertificateData(commonName: String, certificateData: ByteArray): ValidationResult {
        val fingerprint = cryptoProvider.hashSha256(certificateData)
        return validateFingerprint(commonName, fingerprint)
    }

    fun validateCertificate(certificate: X509Certificate) {
        val key = certificate.publicKey.encoded
        val fingerprint = cryptoProvider.hashSha256(key)
        certificate.subjectDN
    }

}