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

import com.wultra.android.sslpinning.interfaces.CryptoProvider
import java.net.URL
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
         * Defines JSON data with a fallback certificate fingerprint.
         *
         * You can configure a fallback certificate which will be used as the last stand during
         * the fingerprint validation.
         *
         * The JSON should contain the same data as are usually received from the server,
         * except that "signature" is not validated (but has to be provided in the JSON).
         * For example:
         * ```val fallbackData = """
         * {
         *     "name" : "www.google.com",
         *     "fingerprint" : "nu1DOBz31Y5FY6lRNkJV/HdnB6BDVCp7mX0nxkbub7Y=",
         *     "expires" : 1540280280000,
         *     "signature" : ""
         * }
         * """.toByteArray()
         */
        val fallbackCertificateData: ByteArray?,

        /**
         * Defines how often (in milliseconds) will [CertStore] periodically check the certificates
         * when there's no certificate to be expired soon.
         *
         * The default value is one week in milliseconds.
         */
        val periodicUpdateIntervalMillis: Long,

        /**
         * Defines the time window in milliseconds before some certificate expires.
         *
         * The default value is two weeks in milliseconds.
         */
        val expirationUpdateThresholdMillis: Long) {

    private constructor(builder: Builder) : this(serviceUrl = builder.serviceUrl,
            publicKey = builder.publicKey,
            expectedCommonNames = builder.expectedCommonNames,
            identifier = builder.identifier,
            fallbackCertificateData = builder.fallbackCertificateData,
            periodicUpdateIntervalMillis = builder.periodicUpdateIntervalMillis,
            expirationUpdateThresholdMillis = builder.expirationUpdateThresholdMillis)

    internal fun validate(cryptoProvider: CryptoProvider) {
        TODO()
    }

    class Builder(
            val serviceUrl: URL,
            val publicKey: ByteArray
    ) {
        var expectedCommonNames: Array<String>? = null
            private set

        var identifier: String? = null
            private set

        var fallbackCertificateData: ByteArray? = null
            private set

        var periodicUpdateIntervalMillis: Long = TimeUnit.DAYS.toMillis(7)
            private set

        var expirationUpdateThresholdMillis: Long = TimeUnit.DAYS.toMillis(14)
            private set

        fun expectedCommonNames(expectedCommonNames: Array<String>?) = apply {
            this.expectedCommonNames = expectedCommonNames
        }

        fun identifier(identifier: String?) = apply {
            this.identifier = identifier
        }

        fun fallbackCertificateData(fallbackCertificateData: ByteArray?) = apply {
            this.fallbackCertificateData = fallbackCertificateData
        }

        fun periodicUpdateIntervalMillis(periodicUpdateIntervalMillis: Long) = apply {
            this.periodicUpdateIntervalMillis = periodicUpdateIntervalMillis
        }

        fun expirationUpdateThresholdMillis(expirationUpdateThresholdMillis: Long) = apply {
            this.expirationUpdateThresholdMillis = expirationUpdateThresholdMillis
        }

        fun build() = CertStoreConfiguration(this)
    }
}