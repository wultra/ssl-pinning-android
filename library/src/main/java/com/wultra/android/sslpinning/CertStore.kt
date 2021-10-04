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

import android.os.Handler
import android.os.Looper
import android.os.Process
import android.support.annotation.WorkerThread
import android.util.Base64
import com.google.gson.Gson
import com.google.gson.GsonBuilder
import com.wultra.android.sslpinning.interfaces.CryptoProvider
import com.wultra.android.sslpinning.interfaces.SecureDataStore
import com.wultra.android.sslpinning.interfaces.SignedData
import com.wultra.android.sslpinning.model.CachedData
import com.wultra.android.sslpinning.model.CertificateInfo
import com.wultra.android.sslpinning.model.GetFingerprintResponse
import com.wultra.android.sslpinning.service.*
import com.wultra.android.sslpinning.service.UpdateScheduler
import com.wultra.android.sslpinning.util.ByteArrayTypeAdapter
import com.wultra.android.sslpinning.util.CertUtils
import com.wultra.android.sslpinning.util.DateTypeAdapter
import java.lang.IllegalArgumentException
import java.security.cert.X509Certificate
import java.util.*

/**
 * The main class that provides features of the dynamic SSL pinning library.
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
         * Name of HTTP request header in case that challenge is used.
         */
        internal const val REQUEST_CHALLENGE_HEADER = "X-Cert-Pinning-Challenge"
        /**
         * Name of HTTP response header in case that challenge is used. The header name is
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

    constructor(configuration: CertStoreConfiguration,
                cryptoProvider: CryptoProvider,
                secureDataStore: SecureDataStore) : this(configuration, cryptoProvider, secureDataStore, null)

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
            WultraDebug.error("Failed to parse stored fingerprint data: $t")
            return null
        }
    }

    internal fun saveDataToCache(data: CachedData) {
        val encodedData = GSON.toJson(data).toByteArray(Charsets.UTF_8)
        secureDataStore.save(data = encodedData, key = instanceIdentifier)
    }

    internal fun loadFallbackCertificates(): Array<CertificateInfo> {
        val fallbackEntries = configuration.fallbackCertificates?.fingerprints ?: return emptyArray()
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
        val challenge: String?
        val response = try {
            val request = if (configuration.useChallenge) {
                challenge = Base64.encodeToString(cryptoProvider.getRandomData(16), Base64.NO_WRAP)
                RemoteDataRequest(mapOf(REQUEST_CHALLENGE_HEADER to challenge))
            } else {
                challenge = null
                RemoteDataRequest(emptyMap())
            }
            remoteDataProvider.getFingerprints(request)
        } catch (e: Exception) {
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
                        WultraDebug.error("Silent update failed, $t crashed with $e.")
                    }
            thread.start()
        }
    }

    private fun processReceivedData(data: ByteArray, challenge: String?, responseHeaders: Map<String, String>, currentDate: Date): UpdateResult {

        val publicKey = cryptoProvider.importECPublicKey(publicKey = configuration.publicKey)
                ?: throw IllegalArgumentException("Illegal configuration public key")

        // Validate signature in header
        if (configuration.useChallenge) {
            if (challenge == null) {
                // This is an internal library error. In case that "useChallenge" is true,
                // then the challenge must be provided.
                throw IllegalArgumentException("Missing challenge")
            }
            val signatureHeader = responseHeaders[RESPONSE_SIGNATURE_HEADER]
            if (signatureHeader == null) {
                WultraDebug.error("Missing signature header.")
                return UpdateResult.INVALID_SIGNATURE
            }
            val signature = try {
                Base64.decode(signatureHeader, Base64.NO_WRAP)
            } catch (t: Throwable) {
                WultraDebug.error("Failed to decode signature from header: $t")
                return UpdateResult.INVALID_SIGNATURE
            }
            var signedBytes = challenge.toByteArray(Charsets.UTF_8)
            signedBytes += '&'.code.toByte()
            signedBytes += data
            if (!cryptoProvider.ecdsaValidateSignatures(SignedData(signedBytes, signature), publicKey)) {
                WultraDebug.error("Invalid signature in $RESPONSE_SIGNATURE_HEADER header")
                return UpdateResult.INVALID_SIGNATURE
            }
        }

        val response = try {
            GSON.fromJson(String(data), GetFingerprintResponse::class.java)
        } catch (t: Throwable) {
            WultraDebug.error("Failed to parse received fingerprint data: $t")
            null
        } ?: return UpdateResult.INVALID_DATA

        // this can be null as it's serialize
        @Suppress("SENSELESS_COMPARISON")
        if (response.fingerprints == null) {
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

                if (!configuration.useChallenge) {
                    // Validate partial signature
                    val signedData = entry.dataForSignature()
                    if (signedData == null) {
                        // Failed to construct bytes for signature validation. I think this may
                        // never happen, unless "entry.name" contains some invalid UTF8 chars.
                        WultraDebug.error("CertStore: Failed to prepare data for signature validation. CN = '${entry.name}'")
                        result = UpdateResult.INVALID_DATA
                        break
                    }

                    if (!cryptoProvider.ecdsaValidateSignatures(signedData, publicKey)) {
                        // detected invalid signature
                        WultraDebug.error("CertStore: Invalid signature detected. CN = '${entry.name}'")
                        result = UpdateResult.INVALID_SIGNATURE
                        break
                    }
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

            if (result == UpdateResult.OK && newCertificates.isEmpty()) {
                // looks like it's time to update list of certificates stored on the server
                WultraDebug.warning("CertStore: Database after update is still empty.")
                result = UpdateResult.STORE_IS_EMPTY
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
            return@updateCachedData CachedData(certificates = certArray, nextUpdate = nextUpdate)
        }
        return result
    }

    /*** VALIDATION ***/

    /**
     * Validates whether provided certificate fingerprint is trusted for given common name.
     *
     * @param commonName A common name
     * @param fingerprint A SHA-256 fingerprint calculated from certificate's data
     *
     * @return Validation result
     */
    fun validateFingerprint(commonName: String, fingerprint: ByteArray): ValidationResult {
        val expected = configuration.expectedCommonNames
        if (expected != null && !expected.contains(commonName)) {
            notifyValidationObservers(commonName, ValidationObserver::onValidationUntrusted)
            return ValidationResult.UNTRUSTED
        }

        val certificates = getCertificates()
        if (certificates.isEmpty()) {
            notifyValidationObservers(commonName, ValidationObserver::onValidationEmpty)
            return ValidationResult.EMPTY
        }

        val now = Date()
        var matchAttempts = 0
        // iterate over all entries and check common name and fingerprint
        // filter out already expired certificates (including the fallback certificate)
        for (info in certificates) {
            if (info.isExpired(now)) {
                continue
            }
            if (info.commonName == commonName) {
                if (info.fingerprint.contentEquals(fingerprint)) {
                    notifyValidationObservers(commonName, ValidationObserver::onValidationTrusted)
                    return ValidationResult.TRUSTED
                }
                matchAttempts += 1
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
     * @return Validation result.
     */
    fun validateCertificateData(commonName: String, certificateData: ByteArray): ValidationResult {
        val fingerprint = cryptoProvider.hashSha256(certificateData)
        return validateFingerprint(commonName, fingerprint)
    }

    /**
     * Validates whether provided certificate is trusted.
     *
     * @param certificate Certificate to test.
     * @return Validation result.
     */
    fun validateCertificate(certificate: X509Certificate): ValidationResult {
        val key = certificate.encoded
        val fingerprint = cryptoProvider.hashSha256(key)
        val commonName = CertUtils.parseCommonName(certificate)
        return validateFingerprint(commonName, fingerprint)
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