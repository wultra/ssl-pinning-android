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

package com.wultra.android.sslpinning.model

import android.util.Base64
import com.wultra.android.sslpinning.interfaces.SignedData
import java.util.*
import java.util.concurrent.TimeUnit

/**
 * Data class for JSON response received from the server.
 *
 * @property fingerprints List of entry objects
 * @author Tomas Kypta, tomas.kypta@wultra.com
 */
data class GetFingerprintResponse(val fingerprints: Array<Entry>) {

    /**
     * Data class for an item in JSON response received from the server.
     *
     * @property name Common name
     * @property fingerprint Fingerprint data
     * @property expires Expiration date
     * @property signature ECDSA signature, optional for servers that supports challenge in request
     *                     and provides signature for the whole response.
     */
    data class Entry(val name: String,
                     val fingerprint: ByteArray,
                     val expires: Date,
                     val signature: ByteArray?) {

        /**
         * Get normalized data which can be used for the signature validation.
         */
        internal fun dataForSignature(): SignedData? {
            if (signature == null) {
                return null
            }
            val expirationTimestampInSeconds = TimeUnit.MILLISECONDS.toSeconds(expires.time)
            val fingerprintPart = String(Base64.encode(fingerprint, Base64.NO_WRAP))
            val signedString = "${name}&${fingerprintPart}&${expirationTimestampInSeconds}"
            return SignedData(data = signedString.toByteArray(Charsets.UTF_8), signature = signature)
        }

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false

            other as Entry

            if (name != other.name) return false
            if (!fingerprint.contentEquals(other.fingerprint)) return false
            if (expires != other.expires) return false
            if (signature != null) {
                if (other.signature == null) return false
                if (!signature.contentEquals(other.signature)) return false
            } else if (other.signature != null) return false

            return true
        }

        override fun hashCode(): Int {
            var result = name.hashCode()
            result = 31 * result + fingerprint.contentHashCode()
            result = 31 * result + expires.hashCode()
            result = 31 * result + (signature?.contentHashCode() ?: 0)
            return result
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as GetFingerprintResponse

        if (!fingerprints.contentEquals(other.fingerprints)) return false

        return true
    }

    override fun hashCode(): Int {
        return fingerprints.contentHashCode()
    }
}