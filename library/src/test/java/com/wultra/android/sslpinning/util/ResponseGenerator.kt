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

package com.wultra.android.sslpinning.util

import java.util.Base64

/**
 * Helper class for generating test fingerprint response JSON for unit tests.
 *
 * Usage:
 * ```
 * val json = ResponseGenerator()
 *     .append(commonName = "example.com", fingerprint = TestConstants.FINGERPRINT_1, depth = 0)
 *     .setDomainsConfig(domainsConfigJson = """{"sslPinningRequiredForUnlisted":true,"domains":[...]}""")
 *     .toJson()
 * ```
 */
class ResponseGenerator {

    private data class Entry(
        val commonName: String,
        val fingerprintBase64: String,
        val depth: Int?
    )

    private val entries = mutableListOf<Entry>()
    private var domainsConfigJson: String? = null

    /**
     * Appends a new entry at the end of fingerprints.
     */
    fun append(commonName: String, fingerprint: ByteArray, depth: Int? = null): ResponseGenerator {
        entries.add(Entry(commonName, Base64.getEncoder().encodeToString(fingerprint), depth))
        return this
    }

    /**
     * Sets a raw JSON string for the domainsConfig field.
     */
    fun setDomainsConfigJson(json: String?): ResponseGenerator {
        domainsConfigJson = json
        return this
    }

    /**
     * Removes all stored entries and clears domainsConfig.
     */
    fun removeAll(): ResponseGenerator {
        entries.clear()
        domainsConfigJson = null
        return this
    }

    /**
     * Generates the response JSON as a ByteArray suitable for use with a mocked RemoteDataProvider.
     *
     * Uses a fake but non-null signature so the GSON model parses correctly.
     * Tests should mock [com.wultra.android.sslpinning.interfaces.CryptoProvider.ecdsaValidateSignature]
     * to return `true`.
     */
    fun toByteArray(): ByteArray {
        val fakeSignature = Base64.getEncoder().encodeToString(ByteArray(64))
        // Expiration far in the future: year 2040
        val expires = 2212460799L

        val entriesJson = entries.joinToString(",\n") { entry ->
            val depthField = if (entry.depth != null) ""","depth": ${entry.depth}""" else ""
            """{
                "name": "${entry.commonName}",
                "fingerprint": "${entry.fingerprintBase64}",
                "expires": $expires,
                "signature": "$fakeSignature"$depthField
            }"""
        }

        val domainsConfigField = if (domainsConfigJson != null) {
            ""","domainsConfig": $domainsConfigJson"""
        } else {
            ""
        }

        return """{"fingerprints": [$entriesJson]$domainsConfigField}""".toByteArray()
    }
}
