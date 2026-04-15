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

import android.content.Context
import android.os.Handler
import android.os.Looper
import android.os.Process
import android.util.Base64
import androidx.annotation.WorkerThread
import com.google.gson.Gson
import com.google.gson.GsonBuilder
import com.wultra.android.sslpinning.integration.DefaultCryptoProvider
import com.wultra.android.sslpinning.integration.DefaultSecureDataStore
import com.wultra.android.sslpinning.interfaces.CryptoProvider
import com.wultra.android.sslpinning.interfaces.SecureDataStore
import com.wultra.android.sslpinning.interfaces.SignedData
import com.wultra.android.sslpinning.model.CachedData
import com.wultra.android.sslpinning.model.CertificateInfo
import com.wultra.android.sslpinning.model.GetFingerprintResponse
import com.wultra.android.sslpinning.service.*
import com.wultra.android.sslpinning.util.ByteArrayTypeAdapter
import com.wultra.android.sslpinning.util.CertUtils
import com.wultra.android.sslpinning.util.DateTypeAdapter
import java.security.cert.X509Certificate
import java.util.Date

/**
 * The main class that provides features of the dynamic SSL pinning library.
 *
 * @author Tomas Kypta, tomas.kypta@wultra.com
 */
class CertStore internal constructor(
    private val configuration: CertStoreConfiguration,
    private val cryptoProvider: CryptoProvider,
    private val secureDataStore: SecureDataStore,
    remoteDataProvider: RemoteDataProvider?
) {

    private val remoteDataProvider: RemoteDataProvider


    @Volatile
    private var cacheIsLoaded = false
    private var cachedData: CachedData? = null
    private var fallbackCertificates = emptyArray<CertificateInfo>()

    private val validationObservers: MutableSet<ValidationObserver> = mutableSetOf()
    private val mainThreadHandler = Handler(Looper.getMainLooper())

    companion object {
        /**
         * Internal instance of GSON.
         */
        internal val GSON: Gson = GsonBuilder()
                .registerTypeAdapter(ByteArray::class.java, ByteArrayTypeAdapter())
                .registerTypeAdapter(Date::class.java, DateTypeAdapter())
                .create()

        /**
         * Name of HTTP request header carrying the random challenge.
         */
        internal const val REQUEST_CHALLENGE_HEADER = "X-Cert-Pinning-Challenge"
        /**
         * Name of HTTP response header carrying the ECDSA signature. The header name is
         * lowercase to properly match various name forms (lowercase, capitalized, etc...)
         */
        internal const val RESPONSE_SIGNATURE_HEADER = "x-cert-pinning-signature"
    }

    init {
        configuration.validate()
        if (remoteDataProvider != null) {
            this.remoteDataProvider = remoteDataProvider
        } else {
            this.remoteDataProvider = RestApi(baseUrl = configuration.serviceUrl, sslValidationStrategy = configuration.sslValidationStrategy)
        }
    }

    constructor(
        configuration: CertStoreConfiguration,
        context: Context
    ) : this(configuration, DefaultCryptoProvider(), DefaultSecureDataStore(context))

    constructor(
        configuration: CertStoreConfiguration,
        cryptoProvider: CryptoProvider,
        secureDataStore: SecureDataStore
    ) : this(configuration, cryptoProvider, secureDataStore, null)

    /**
     * Identifier of the instance.
     * When nothing was provided "default" is returned.
     */
    val instanceIdentifier: String
        get() {
            return configuration.identifier ?: "default"
        }

    /**
     * Reset [CertStore] data.
     */
    @Synchronized
    fun reset() {
        WultraDebug.warning("CertStore: reset() should not be used in production build.")
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
        return cachedData?.let { it.certificates + fallbackCertificates } ?: fallbackCertificates
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
            fallbackCertificates = loadFallbackCertificates()
            cacheIsLoaded = true
        }
    }

    /*** STORAGE ***/

    internal fun loadCachedData(): CachedData? {
        val encodedData = secureDataStore.load(key = instanceIdentifier) ?: return null
        return try {
            GSON.fromJson(String(encodedData), CachedData::class.java)
        } catch (t: Throwable) {
            WultraDebug.error("CertStore: Failed to parse stored fingerprint data: $t")
            return null
        }
    }

    internal fun saveDataToCache(data: CachedData) {
        val encodedData = GSON.toJson(data).toByteArray(Charsets.UTF_8)
        secureDataStore.save(data = encodedData, key = instanceIdentifier)
    }

    internal fun loadFallbackCertificates(): Array<CertificateInfo> {
        // In the current implementation, we deliberately do not allow fallback configuration for domains;
        // only the fallback certificates array is supported.
        val fallbackEntries = configuration.fallbackCertificates ?: return emptyArray()
        return fallbackEntries.map { CertificateInfo(it) }.toTypedArray()
    }

    /*** UPDATE ***/

    /**
     * Tells `CertStore` to update its database of certificates from the remote location.
     *
     * The method checks if the update is necessary based on the stored data and update mode.
     * It internally computes [UpdateType] as in [getUpdateType] method.
     * The observer returns [UpdateType] in [UpdateObserver.onUpdateStarted] method after
     * the method is called. And [UpdateObserver.onUpdateFinished] with [UpdateResult]
     * is called after update was performed.
     *
     * If the method decides update is not necessary ([UpdateType.NO_UPDATE]),
     * it will not start the update and [UpdateObserver.onUpdateFinished] is called after
     * [UpdateObserver.onUpdateStarted].
     *
     * In every case both callbacks [UpdateObserver.onUpdateStarted]
     * and [UpdateObserver.onUpdateFinished] are always called.
     *
     * The update is scheduled either on an [java.util.concurrent.ExecutorService] provided in the configuration
     * or on a dedicated [Thread] if no [java.util.concurrent.ExecutorService] was defined in the configuration.
     *
     * The update observer is delivered on the main thread.
     * The update observer is held with a strong reference.
     *
     * @param mode Update mode.
     * @param updateObserver Observer for [UpdateType] and [UpdateResult].
     */
    fun update(mode: UpdateMode = UpdateMode.DEFAULT, updateObserver: UpdateObserver) {
        val now = Date()
        val updateType = if (mode == UpdateMode.FORCED) {
            UpdateType.DIRECT
        } else {
            getUpdateType()
        }

        mainThreadHandler.post {
            updateObserver.onUpdateStarted(updateType)
        }

        if (!updateType.isPerformingUpdate) {
            mainThreadHandler.post {
                updateObserver.onUpdateFinished(updateType, UpdateResult.OK)
            }
        } else {
            doUpdateAsync(now, updateType, updateObserver)
        }
    }

    /**
     * Get type of an update (either direct or silent) that would be started
     * based on the cached fingerprint data when started with [UpdateMode.DEFAULT].
     *
     * @return Type of the update that would be performed.
     *
     * @since 0.9.0
     */
    fun getUpdateType(): UpdateType {
        val now = Date()
        val cachedData = getCachedData()

        if (cachedData == null) {
            return UpdateType.DIRECT
        } else {
            if (cachedData.numberOfValidCertificates(now) == 0) {
                return UpdateType.DIRECT
            }

            if (cachedData.nextUpdate.before(now)) {
                return UpdateType.SILENT
            }
        }
        return UpdateType.NO_UPDATE
    }

    @WorkerThread
    private fun doUpdate(currentDate: Date): UpdateResult {
        val challenge = Base64.encodeToString(cryptoProvider.getRandomData(16), Base64.NO_WRAP)
        val response = try {
            remoteDataProvider.getFingerprints(RemoteDataRequest(mapOf(REQUEST_CHALLENGE_HEADER to challenge)))
        } catch (e: Exception) {
            WultraDebug.error("Failed to update: ${e.message}")
            return UpdateResult.NETWORK_ERROR
        }
        return processReceivedData(response.data, challenge, response.responseHeaders, currentDate)
    }

    private fun doUpdateAsync(currentDate: Date, updateType: UpdateType, updateObserver: UpdateObserver) {
        val updateRunnable = Runnable {
            val result = doUpdate(currentDate)
            mainThreadHandler.post {
                updateObserver.onUpdateFinished(updateType, result)
            }
        }

        configuration.executorService?.submit(updateRunnable) ?: run {
            // run on a dedicated thread as a fallback
            val thread = Thread(updateRunnable)
            thread.name = "SilentCertStoreUpdate"
            thread.priority = Process.THREAD_PRIORITY_BACKGROUND
            thread.uncaughtExceptionHandler =
                    Thread.UncaughtExceptionHandler { t, e ->
                        WultraDebug.error("CertStore: Silent update failed, $t crashed with $e.")
                    }
            thread.start()
        }
    }

    private fun processReceivedData(data: ByteArray, challenge: String, responseHeaders: Map<String, String>, currentDate: Date): UpdateResult {

        val publicKey = cryptoProvider.importECPublicKey(publicKey = configuration.publicKey)
                ?: throw IllegalArgumentException("Illegal configuration public key")

        // Validate signature in header
        val signatureHeader = responseHeaders[RESPONSE_SIGNATURE_HEADER]
        if (signatureHeader == null) {
            WultraDebug.error("CertStore: Missing signature header.")
            return UpdateResult.INVALID_SIGNATURE
        }
        val signature = try {
            Base64.decode(signatureHeader, Base64.NO_WRAP)
        } catch (t: Throwable) {
            WultraDebug.error("CertStore: Failed to decode signature from header: $t")
            return UpdateResult.INVALID_SIGNATURE
        }
        var signedBytes = challenge.toByteArray(Charsets.UTF_8)
        signedBytes += '&'.code.toByte()
        signedBytes += data
        if (!cryptoProvider.ecdsaValidateSignature(SignedData(signedBytes, signature), publicKey)) {
            WultraDebug.error("CertStore: Invalid signature in $RESPONSE_SIGNATURE_HEADER header")
            return UpdateResult.INVALID_SIGNATURE
        }

        val response = try {
            GSON.fromJson(String(data), GetFingerprintResponse::class.java)
        } catch (t: Throwable) {
            WultraDebug.error("CertStore: Failed to parse received fingerprint data: $t")
            null
        } ?: return UpdateResult.INVALID_DATA

        // This can be null as it's serialized.
        @Suppress("SENSELESS_COMPARISON")
        if (response.fingerprints == null) {
            WultraDebug.error("CertStore: Fingerprints are null")
            // this can be caused by invalid data in json
            return UpdateResult.INVALID_DATA
        }

        var result = UpdateResult.OK
        updateCachedData { cachedData ->
            val newCertificates = (cachedData?.certificates ?: arrayOf())
                    .filter { !it.isExpired(currentDate) }
                    .toMutableList()

            for (entry in response.fingerprints) {
                val newCertificateInfo = CertificateInfo(entry)
                if (newCertificateInfo.isExpired(currentDate)) {
                    // skip already expired entry
                    continue
                }

                if (newCertificates.indexOf(newCertificateInfo) != -1) {
                    // skip entry that's already in the database
                    continue
                }

                configuration.expectedCommonNames?.let { expectedCN ->
                    if (!expectedCN.contains(newCertificateInfo.commonName)) {
                        // CertStore will store this CertificateInfo, but validation will ignore
                        // this entry because it's not in expectedCommonNames
                        WultraDebug.warning("CertStore: Loaded data contains name, which will not be trusted. CN = '${entry.name}'")
                    }
                }

                newCertificates.add(newCertificateInfo)
            }

            if (result != UpdateResult.OK) {
                return@updateCachedData null
            }

            newCertificates.sort()
            val certArray = newCertificates.toTypedArray()

            val scheduler = UpdateScheduler(
                    periodicUpdateIntervalMillis = configuration.periodicUpdateIntervalMillis,
                    expirationUpdateThresholdMillis = configuration.expirationUpdateThresholdMillis,
                    thresholdMultiplier = 0.125)
            val nextUpdate = scheduler.scheduleNextUpdate(certArray, currentDate)
            return@updateCachedData CachedData(
                certificates = certArray,
                nextUpdate = nextUpdate,
                domainsConfig =  response.domainsConfig)
        }
        return result
    }

    /*** VALIDATION ***/

    /**
     * Validates whether provided certificate fingerprint at a specific chain depth is trusted for given common name.
     *
     * When [com.wultra.android.sslpinning.model.DomainsConfig] is available from a server update and the domain has [com.wultra.android.sslpinning.model.DomainConfig.sslPinningRequired]
     * set to `false`, the validation returns [ValidationResult.TRUSTED] immediately without checking the fingerprint.
     *
     * @param commonName A common name from the leaf server certificate
     * @param fingerprint A SHA-256 fingerprint calculated from certificate's data
     * @param depth The certificate depth in the TLS chain (0 = leaf, 1..N-1 = intermediate, N = root). When no depth is provided, 0 is used as default.
     *
     * @return Validation result
     */
    @JvmOverloads
    fun validateFingerprint(commonName: String, fingerprint: ByteArray, depth: Int = 0): ValidationResult {
        // Check domainsConfig as early as possible
        if (!isDomainsConfigPinningRequired(commonName)) {
            notifyValidationObservers(commonName, ValidationObserver::onValidationTrusted)
            return ValidationResult.TRUSTED
        }

        // depth should be 0+
        if (depth < 0) {
            WultraDebug.warning("CertStore: Requested depth of certificate should be >= 0; returning UNTRUSTED without fingerprint validation.")
            notifyValidationObservers(commonName, ValidationObserver::onValidationUntrusted)
            return ValidationResult.UNTRUSTED
        }

        val expected = configuration.expectedCommonNames
        if (expected != null && !expected.contains(commonName)) {
            WultraDebug.warning("CertStore: Common name '$commonName' not found in expected list; returning UNTRUSTED without fingerprint validation.")
            notifyValidationObservers(commonName, ValidationObserver::onValidationUntrusted)
            return ValidationResult.UNTRUSTED
        }

        val certificates = getCertificates()
        if (certificates.isEmpty()) {
            WultraDebug.warning("CertStore: List of certificates is empty; returning EMPTY.")
            notifyValidationObservers(commonName, ValidationObserver::onValidationEmpty)
            return ValidationResult.EMPTY
        }

        val now = Date()
        var matchAttempts = 0
        // Iterate over all entries and look for common name & fingerprint.
        // Also filter out already expired certificates (including the fallback certificate).
        for (info in certificates) {
            if (info.isExpired(now)) {
                continue
            }
            if (info.commonName == commonName && info.depth == depth) {
                matchAttempts += 1
                if (info.fingerprint.contentEquals(fingerprint)) {
                    notifyValidationObservers(commonName, ValidationObserver::onValidationTrusted)
                    return ValidationResult.TRUSTED
                }
            }
        }

        return if (matchAttempts > 0) {
            notifyValidationObservers(commonName, ValidationObserver::onValidationUntrusted)
            ValidationResult.UNTRUSTED
        } else {
            notifyValidationObservers(commonName, ValidationObserver::onValidationEmpty)
            ValidationResult.EMPTY
        }
    }

    /**
     * Validates whether provided certificate data in DER format is trusted for given common name.
     *
     * @param commonName Common name (CN).
     * @param certificateData Certificate data in DER format.
     * @param depth The certificate depth in the TLS chain (0 = leaf, 1..N-1 = intermediate, N = root). When no depth is provided, 0 is used as default.
     * @return Validation result.
     */
    @JvmOverloads
    fun validateCertificateData(commonName: String, certificateData: ByteArray, depth: Int = 0): ValidationResult {
        // Check domainsConfig as early as possible — skip SHA-256 when pinning is not required
        if (!isDomainsConfigPinningRequired(commonName)) {
            notifyValidationObservers(commonName, ValidationObserver::onValidationTrusted)
            return ValidationResult.TRUSTED
        }
        val fingerprint = cryptoProvider.hashSha256(certificateData)
        return validateFingerprint(commonName, fingerprint, depth)
    }

    /**
     * Validates whether provided certificate is trusted.
     * Validates the leaf certificate (depth 0), which is the default behavior.
     *
     * @param certificate Certificate to test.
     * @return Validation result.
     */
    fun validateCertificate(certificate: X509Certificate): ValidationResult {
        return validateCertificateData(CertUtils.parseCommonName(certificate), certificate.encoded, 0)
    }

    /**
     * Validates whether the provided TLS certificate chain is trusted by checking all pinned entries
     * across every depth.
     *
     * The common name is extracted from the leaf certificate (chain[0]). All pinned entries for that
     * common name are then checked against the certificates in the chain at their respective stored
     * depths. At least one pinned entry must match for the chain to be considered trusted.
     *
     * @param chain The TLS certificate chain, where chain[0] is the leaf certificate.
     * @return Validation result.
     */
    fun validateCertificateChain(chain: Array<out X509Certificate>): ValidationResult {
        if (chain.isEmpty()) {
            WultraDebug.warning("CertStore: Certificate chain is empty; returning UNTRUSTED without fingerprint validation.")
            notifyValidationObservers("empty chain", ValidationObserver::onValidationUntrusted)
            return ValidationResult.UNTRUSTED
        }

        val commonName = CertUtils.parseCommonName(chain[0])
        // Check domainsConfig as early as possible
        if (!isDomainsConfigPinningRequired(commonName)) {
            notifyValidationObservers(commonName, ValidationObserver::onValidationTrusted)
            return ValidationResult.TRUSTED
        }

        // Check expected common names
        val expected = configuration.expectedCommonNames
        if (expected != null && !expected.contains(commonName)) {
            WultraDebug.warning("CertStore: Common name '$commonName' not found in expected list; returning UNTRUSTED without fingerprint validation.")
            notifyValidationObservers(commonName, ValidationObserver::onValidationUntrusted)
            return ValidationResult.UNTRUSTED
        }

        val certificates = getCertificates()
        if (certificates.isEmpty()) {
            WultraDebug.warning("CertStore: List of certificates is empty; returning EMPTY.")
            notifyValidationObservers(commonName, ValidationObserver::onValidationEmpty)
            return ValidationResult.EMPTY
        }

        val now = Date()
        var matchAttempts = 0

        for (info in certificates) {
            if (info.isExpired(now)) {
                continue
            }
            if (info.commonName != commonName) {
                continue
            }

            val pinnedDepth = info.depth
            if (pinnedDepth < 0 || pinnedDepth >= chain.size) {
                WultraDebug.warning("CertStore: Skipping pinned certificate for common name '$commonName' because configured depth $pinnedDepth is out of range for certificate chain size ${chain.size}.")
                continue
            }

            val fingerprint = cryptoProvider.hashSha256(chain[pinnedDepth].encoded)
            matchAttempts += 1

            if (info.fingerprint.contentEquals(fingerprint)) {
                notifyValidationObservers(commonName, ValidationObserver::onValidationTrusted)
                return ValidationResult.TRUSTED
            }
        }

        return if (matchAttempts > 0) {
            notifyValidationObservers(commonName, ValidationObserver::onValidationUntrusted)
            ValidationResult.UNTRUSTED
        } else {
            notifyValidationObservers(commonName, ValidationObserver::onValidationEmpty)
            ValidationResult.EMPTY
        }
    }

    /**
     * Returns whether SSL pinning is required for the given domain name according to [DomainsConfig].
     *
     * When no [DomainsConfig] is available (e.g. not yet fetched from the server), pinning is
     * considered required. When [DomainsConfig] is present, its per-domain or fallback value is used.
     *
     * @param commonName The domain name to check.
     * @return `false` when [DomainsConfig] explicitly disables pinning for this domain; `true` otherwise.
     */
    private fun isDomainsConfigPinningRequired(commonName: String): Boolean {
        val domainsConfig = getCachedData()?.domainsConfig ?: return true
        val required = domainsConfig.isPinningRequired(commonName)
        if (!required) {
            WultraDebug.warning("CertStore: Pinning disabled by domainsConfig for domain '$commonName'; returning TRUSTED without fingerprint validation.")
        }
        return required
    }

    /*** GLOBAL VALIDATION OBSERVERS ***/

    /**
     * Add global validation observer to be notified about all validation failures (
     * either [ValidationResult.UNTRUSTED] or [ValidationResult.EMPTY]).
     *
     * All observers are held with a strong reference.
     *
     * @param observer Observer to be added.
     *
     * @since 0.9.0
     */
    fun addValidationObserver(observer: ValidationObserver) {
        synchronized(validationObservers) {
            validationObservers.add(observer)
        }
    }

    /**
     * Remove global validation observer.
     *
     * @param observer Observer to be removed.
     *
     * @since 0.9.0
     */
    fun removeValidationObserver(observer: ValidationObserver) {
        if (!validationObservers.contains(observer)) {
            throw IllegalArgumentException("Cannot remove unknown ValidationObserver")
        }
        synchronized(validationObservers) {
            validationObservers.remove(observer)
        }
    }

    /**
     * Remove all global validation observers.
     *
     * @since 0.9.0
     */
    fun removeAllValidationObservers() {
        synchronized(validationObservers) {
            validationObservers.clear()
        }
    }

    /**
     * Notify all global validation observers with callback about a validation failure.
     *
     * The observers are notified on the main thread.
     *
     * @param commonName Notify that there was a problem with validation of this common name.
     * @param observerCallback Notify all observers with this validation observer callback.
     *
     * @since 0.9.0
     */
    private fun notifyValidationObservers(commonName: String, observerCallback: ValidationObserver.(String) -> Unit) {
        synchronized(validationObservers) {
            validationObservers.forEach { observer ->
                mainThreadHandler.post {
                    observer.observerCallback(commonName)
                }
                return@forEach
            }
        }
    }
}