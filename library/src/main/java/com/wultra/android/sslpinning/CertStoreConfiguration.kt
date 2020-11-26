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

import com.wultra.android.sslpinning.model.GetFingerprintResponse
import com.wultra.android.sslpinning.service.WultraDebug
import java.lang.IllegalArgumentException
import java.net.URL
import java.util.*
import java.util.concurrent.ExecutorService
import java.util.concurrent.TimeUnit

/**
 * Configuration for [CertStore].
 *
 * It's necessary to construct with at least [serviceUrl] and [publicKey] properties.
 *
 * @author Tomas Kypta, tomas.kypta@wultra.com
 */
class CertStoreConfiguration(

        /**
         * URL for getting certificate fingerprints.
         */
        val serviceUrl: URL,

        /**
         * ECC public key which will be used for validating data received from the server.
         * A Base64 string is expected.
         * If an invalid key is provided, the library will crash with a fatal error on the first
         * attempt to use the public key.
         */
        val publicKey: ByteArray,

        /**
         * Indicates that server providing certificate fingerprints requires a random challenge
         * and provides response signed with ECDSA signature.
         */
        val useChallenge: Boolean,

        /**
         * Optional property defining the set of common names which are expected in certificate
         * validation.
         * By setting this property you instruct the store to treat all certificates issued for other
         * common names as untrusted.
         */
        val expectedCommonNames: Array<String>?,

        /**
         * Defines instance identifier for the case when an application requires more than one instance
         * of [CertStore]. The identifier is then used for data identification in the underlying
         * persistent data storage.
         *
         * When not provided, the [CertStore] will use "default" string constant for the identification.
         */
        val identifier: String?,

        /**
         * Defines a fallback certificate fingerprints.
         *
         * You can configure a fallback certificate which will be used as the last stand during
         * the fingerprint validation.
         */
        val fallbackCertificates: GetFingerprintResponse?,

        /**
         * Defines how often (in milliseconds) will [CertStore] periodically check the certificates
         * when there's no certificate to be expired soon.
         *
         * The default value is one week in milliseconds.
         */
        val periodicUpdateIntervalMillis: Long,

        /**
         * Defines the time window in milliseconds before a certificate expires.
         *
         * The default value is two weeks in milliseconds.
         */
        val expirationUpdateThresholdMillis: Long,

        /**
         * Executor service on which silent updates will run.
         * If not set, the silent updates will run on a separate thread.
         */
        val executorService: ExecutorService? = null,

        /**
         * SSL validation strategy applied to HTTPS requests initiated from this library.
         * If not set, then the default system-provided certificate chain validation will be used.
         */
        val sslValidationStrategy: SslValidationStrategy? = null) {

    private constructor(builder: Builder) : this(serviceUrl = builder.serviceUrl,
            publicKey = builder.publicKey,
            useChallenge = builder.useChallenge,
            expectedCommonNames = builder.expectedCommonNames,
            identifier = builder.identifier,
            fallbackCertificates = builder.fallbackCertificates ?: builder.fallbackCertificate?.let { GetFingerprintResponse(arrayOf(it)) },
            periodicUpdateIntervalMillis = builder.periodicUpdateIntervalMillis,
            expirationUpdateThresholdMillis = builder.expirationUpdateThresholdMillis,
            executorService = builder.executorService,
            sslValidationStrategy = builder.sslValidationStrategy)

    /**
     * Validate that the configuration doesn't contain any errors.
     */
    internal fun validate() {
        if (serviceUrl.protocol == "http") {
            WultraDebug.warning("CertStoreConfiguration: 'serviceUrl' should point to 'https' server.")
        }
        if (sslValidationStrategy != null) {
            WultraDebug.warning("CertStoreConfiguration: 'sslValidationStrategy' should not be used in production.")
        }
        // validate fallback certificate data
        fallbackCertificates?.fingerprints?.forEach { fallback ->
            try {
                expectedCommonNames?.let { expectedCNs ->
                    if (!expectedCNs.contains(fallback.name)) {
                        WultraDebug.warning("CertStoreConfiguration: 'fallbackCertificate' is issued for common name " +
                                "which is not included in 'expectedCommonNames'.")
                    }
                    if (fallback.expires.before(Date())) {
                        WultraDebug.warning("CertStoreConfiguration: 'fallbackCertificate' is already expired.")
                    }
                }
            } catch (t: Throwable) {
                WultraDebug.error("CertStoreConfiguration: 'fallbackCertificates' contains invalid JSON.")
            }

        }

        // TODO improve with validation of public key

        if (periodicUpdateIntervalMillis < 0) {
            throw IllegalArgumentException("CertStoreConfiguration: 'periodicUpdateIntervalMillis' contains negative value.")
        }
        if (expirationUpdateThresholdMillis < 0) {
            throw IllegalArgumentException("CertStoreConfiguration: 'expirationUpdateThresholdMillis' contains negative value.")
        }
    }

    /**
     * Builder for constructing [CertStoreConfiguration].
     *
     * @param serviceUrl URL of remote update server.
     * @param publicKey Public key for validating data received from the server.
     */
    @Suppress("DeprecatedCallableAddReplaceWith")
    class Builder(
            val serviceUrl: URL,
            val publicKey: ByteArray
    ) {
        var useChallenge: Boolean = false
            private set

        var expectedCommonNames: Array<String>? = null
            private set

        var identifier: String? = null
            private set

        // TODO: Remove in version 2.0
        @Deprecated("Use [fallbackCertificates] instead.")
        var fallbackCertificate: GetFingerprintResponse.Entry? = null
            private set

        var fallbackCertificates: GetFingerprintResponse? = null
            private set

        var periodicUpdateIntervalMillis: Long = TimeUnit.DAYS.toMillis(7)
            private set

        var expirationUpdateThresholdMillis: Long = TimeUnit.DAYS.toMillis(14)
            private set

        var executorService: ExecutorService? = null
            private set

        var sslValidationStrategy: SslValidationStrategy? = null
            private set

        /**
         * Set use challenge flag.
         *
         * Required for dynamic servers
         */
        fun useChallenge(useChallenge: Boolean) = apply {
            this.useChallenge = useChallenge
        }

        /**
         * Set expected common names.
         */
        fun expectedCommonNames(expectedCommonNames: Array<String>?) = apply {
            this.expectedCommonNames = expectedCommonNames
        }

        /**
         * Set identifier.
         *
         * Necessary for multiple instances of [CertStore].
         * If not set the identifier is "default".
         */
        fun identifier(identifier: String?) = apply {
            this.identifier = identifier
        }

        /**
         * Fallback certificate fingerprint.
         * Useful for situations when no fingerprints has been loaded from the server yet.
         */
        @Deprecated("Use fallbackCertificates instead. This method will be removed in the future.")
        fun fallbackCertificate(fallbackCertificate: GetFingerprintResponse.Entry?) = apply {
            this.fallbackCertificate = fallbackCertificate
        }

        /**
         * Fallback certificate fingerprints.
         * Useful for situations when no fingerprints has been loaded from the server yet.
         */
        fun fallbackCertificates(fallbackCertificates: GetFingerprintResponse?) = apply {
            this.fallbackCertificates = fallbackCertificates
        }

        /**
         * Update interval of fingerprints.
         */
        fun periodicUpdateIntervalMillis(periodicUpdateIntervalMillis: Long) = apply {
            this.periodicUpdateIntervalMillis = periodicUpdateIntervalMillis
        }

        /**
         * Expiration interval for fingerprints.
         */
        fun expirationUpdateThresholdMillis(expirationUpdateThresholdMillis: Long) = apply {
            this.expirationUpdateThresholdMillis = expirationUpdateThresholdMillis
        }

        /**
         * Executor service for performing silent updates of certificate fingerprints.
         */
        fun executorService(executorService: ExecutorService?) = apply {
            this.executorService = executorService
        }

        /**
         * Changes validation strategy how HTTPS requests initiated from this library should be handled.
         * Please read a note about [SslValidationStrategy.noValidation] before you change this option.
         */
        fun sslValidationStrategy(sslValidationStrategy: SslValidationStrategy) = apply {
            this.sslValidationStrategy = sslValidationStrategy
        }

        /**
         * Builds [CertStoreConfiguration].
         */
        fun build() = CertStoreConfiguration(this)
    }
}