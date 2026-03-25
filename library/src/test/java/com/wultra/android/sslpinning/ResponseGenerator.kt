/*
 * Copyright 2026 Wultra s.r.o.
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

import com.wultra.android.sslpinning.model.DomainsConfig
import java.util.Base64
import java.util.Date
import java.util.concurrent.TimeUnit

/**
 * Test helper that builds fingerprint JSON response data for unit tests.
 * Mirrors the iOS `ResponseGenerator` class for consistency across platforms.
 */
internal class ResponseGenerator {

    data class Entry(
        val commonName: String,
        val fingerprint: ByteArray,
        val expiration: Expiration,
        val depth: Int? = null
    )

    enum class Expiration(val offsetMillis: Long) {
        /** Expires one year in the future. */
        VALID(TimeUnit.DAYS.toMillis(365)),
        /** Already expired one day in the past. */
        EXPIRED(-TimeUnit.DAYS.toMillis(1));

        val date: Date get() = Date(System.currentTimeMillis() + offsetMillis)
    }

    private val entries = mutableListOf<Entry>()
    private var domainsConfig: DomainsConfig? = null

    /** Appends a new fingerprint entry. */
    fun append(
        commonName: String,
        expiration: Expiration = Expiration.VALID,
        fingerprint: ByteArray = randomBytes(32),
        depth: Int? = null
    ): ResponseGenerator {
        entries.add(Entry(commonName, fingerprint, expiration, depth))
        return this
    }

    /** Sets the [DomainsConfig] to be included in the response. */
    fun setDomainsConfig(config: DomainsConfig?): ResponseGenerator {
        this.domainsConfig = config
        return this
    }

    /** Removes all entries and clears the [DomainsConfig]. */
    fun removeAll(): ResponseGenerator {
        entries.clear()
        domainsConfig = null
        return this
    }

    /** Generates the JSON response as a byte array. */
    fun data(): ByteArray {
        val fingerprintsJson = entries.joinToString(",\n") { entry ->
            val fingerprintBase64 = Base64.getEncoder().encodeToString(entry.fingerprint)
            val expiresSeconds = TimeUnit.MILLISECONDS.toSeconds(entry.expiration.date.time)
            val depthPart = if (entry.depth != null) ""","depth": ${entry.depth}""" else ""
            val sigBase64 = Base64.getEncoder().encodeToString(randomBytes(64))
            """
            {
              "name": "${entry.commonName}",
              "fingerprint": "$fingerprintBase64",
              "expires": $expiresSeconds,
              "signature": "$sigBase64"$depthPart
            }""".trimIndent()
        }

        val domainsConfigJson = domainsConfig?.let { config ->
            val domainsJson = config.domains.joinToString(",\n") { domain ->
                """{"name": "${domain.name}", "sslPinningRequired": ${domain.sslPinningRequired}}"""
            }
            ""","domainsConfig": {"sslPinningRequiredForUnlisted": ${config.sslPinningRequiredForUnlisted}, "domains": [$domainsJson]}"""
        } ?: ""

        return """{"fingerprints": [$fingerprintsJson]$domainsConfigJson}""".toByteArray()
    }

    companion object {
        fun randomBytes(length: Int): ByteArray = ByteArray(length) { (it % 256).toByte() }
    }
}
