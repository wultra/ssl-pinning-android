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
import com.google.gson.Gson
import com.google.gson.GsonBuilder
import com.wultra.android.sslpinning.interfaces.CryptoProvider
import com.wultra.android.sslpinning.interfaces.SecureDataStore
import com.wultra.android.sslpinning.model.CachedData
import com.wultra.android.sslpinning.model.CertificateInfo
import com.wultra.android.sslpinning.model.GetFingerprintResponse
import com.wultra.android.sslpinning.service.RemoteDataProvider
import com.wultra.android.sslpinning.service.RestApi
import com.wultra.android.sslpinning.service.UpdateScheduler
import com.wultra.android.sslpinning.service.WultraDebug
import com.wultra.android.sslpinning.util.ByteArrayTypeAdapter
import com.wultra.android.sslpinning.util.CertUtils
import com.wultra.android.sslpinning.util.DateTypeAdapter
import java.lang.IllegalArgumentException
import java.security.cert.X509Certificate
import java.util.*

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

    private val validationObservers: MutableSet<ValidationObserver> = mutableSetOf()
    private val mainThreadHandler = Handler(Looper.getMainLooper())

    companion object {
        internal val GSON: Gson = GsonBuilder()
                .registerTypeAdapter(ByteArray::class.java, ByteArrayTypeAdapter())
                .registerTypeAdapter(Date::class.java, DateTypeAdapter())
                .create()
    }

    init {
        configuration.validate()
        if (remoteDataProvider != null) {
            this.remoteDataProvider = remoteDataProvider
        } else {
            this.remoteDataProvider = RestApi(baseUrl = configuration.serviceUrl)
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
        WultraDebug.warning("CertStore: reset() hould not be used in production build.")
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
        var result = cachedData?.certificates ?: arrayOf()
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

    /*** STORAGE ***/

    internal fun loadCachedData(): CachedData? {
        val encodedData = secureDataStore.load(key = instanceIdentifier) ?: return null
        val cachedData = try {
            GSON.fromJson(String(encodedData), CachedData::class.java)
        } catch (t: Throwable) {
            return null
        }
        return cachedData
    }

    internal fun saveDataToCache(data: CachedData) {
        val encodedData = GSON.toJson(data).toByteArray(Charsets.UTF_8)
        secureDataStore.save(data = encodedData, key = instanceIdentifier)
    }

    internal fun loadFallbackCertificate(): CertificateInfo? {
        val fallbackEntry = configuration.fallbackCertificate ?: return null
        return CertificateInfo(fallbackEntry)
    }

    /*** UPDATE ***/

    /**
     * Tells `CertStore` to update its database of certificates from the remote location.
     *
     * This method checks if the update is necessary based on the stored data and update mode.
     * If it decides update is not necessary, it will not start the update and return false.
     *
     * The update is scheduled either on an [ExecutorService] provided in the configuration
     * or on a dedicated [Thread] if no [ExecutorService] was defined in the configuration.
     *
     * The update observer is delivered on the main thread.
     * The update observer is held with a strong reference.
     *
     * @param mode Update mode.
     * @param updateObserver Observer for update result
     * @return True if an update is started in the background, false if no update is started.
     */
    @JvmOverloads
    fun update(mode: UpdateMode = UpdateMode.DEFAULT, updateObserver: UpdateObserver? = null): Boolean {
        val pair = checkUpdateNeededInternal()
        val now = Date()
        var needsDirectUpdate = pair.first || mode == UpdateMode.FORCED
        var needsSilentUpdate = pair.second

        if (needsDirectUpdate) {
            doUpdateAsync(now, updateObserver)
            return true
        } else {
            if (needsSilentUpdate) {
                doUpdateAsync(now, updateObserver)
                return true
            }
        }
        return false
    }

    /**
     * Check if an update (either direct or silent) is necessary based on the cached data.
     *
     * This check performs the same check that happens inside [update] method.
     * If the method returns true, it's recommended to perform an update.
     *
     * @return True if either direct or silent update is necessary.
     *
     * @since 0.9.0
     */
    fun checkUpdateNeeded(): Boolean {
        val pair = checkUpdateNeededInternal()
        return pair.first || pair.second
    }

    private fun checkUpdateNeededInternal(): Pair<Boolean, Boolean> {
        val now = Date()
        val cachedData = getCachedData()
        var needsDirectUpdate = true
        var needsSilentUpdate = false

        cachedData?.let {
            needsDirectUpdate = it.numberOfValidCertificates(now) == 0
            if (!needsDirectUpdate) {
                needsSilentUpdate = it.nextUpdate.before(now)
            }
        }
        return Pair(needsDirectUpdate, needsSilentUpdate)
    }

    @WorkerThread
    private fun doUpdate(currentDate: Date): UpdateResult {
        val bytes = try {
            remoteDataProvider.getFingerprints()
        } catch (e: Exception) {
            return UpdateResult.NETWORK_ERROR
        }
        return processReceivedData(bytes, currentDate)
    }

    private fun doUpdateAsync(currentDate: Date, updateObserver: UpdateObserver? = null) {
        val updateRunnable = Runnable {
            val result = doUpdate(currentDate)
            updateObserver?.let {
                mainThreadHandler.post {
                    updateObserver.onUpdateFinished(result)
                }
            }
        }

        configuration.executorService?.let {
            it.submit(updateRunnable)
        } ?: run {
            // run on a dedicated thread as a fallback
            val thread = Thread(updateRunnable)
            thread.name = "SilentCertStoreUpdate"
            thread.priority = Process.THREAD_PRIORITY_BACKGROUND
            thread.uncaughtExceptionHandler =
                    Thread.UncaughtExceptionHandler { t, e ->
                        WultraDebug.error("Silent update failed, $t crashed with ${e}.")
                    }
            thread.start()
        }
    }

    private fun processReceivedData(data: ByteArray, currentDate: Date): UpdateResult {
        val response = try {
            GSON.fromJson(String(data), GetFingerprintResponse::class.java)
        } catch (t: Throwable) {
            null
        } ?: return UpdateResult.INVALID_DATA

        if (response.fingerprints == null) {
            // this can be caused by invalid data in json
            return UpdateResult.INVALID_DATA
        }

        val publicKey = cryptoProvider.importECPublicKey(publicKey = configuration.publicKey)
                ?: throw IllegalArgumentException("Illegal configuration public key")

        var result = UpdateResult.OK
        updateCachedData { cachedData ->
            var newCertificates = (cachedData?.certificates ?: arrayOf())
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

                configuration.expectedCommonNames?.let { expectedCN ->
                    if (!expectedCN.contains(newCertificateInfo.commonName)) {
                        // CertStore will stor ethis CertificateInfo, but validation will ignore
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