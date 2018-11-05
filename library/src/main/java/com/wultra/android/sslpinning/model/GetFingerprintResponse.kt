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
     * @property signature ECDSA signature
     */
    data class Entry(val name: String,
                     val fingerprint: ByteArray,
                     val expires: Date,
                     val signature: ByteArray) {

        /**
         * Get normalized data which can be used for the signature validation.
         */
        internal fun dataForSignature(): SignedData? {
            val expirationTimestampInSeconds = TimeUnit.MILLISECONDS.toSeconds(expires.time)
            val fingerprintPart = String(Base64.encode(fingerprint, Base64.DEFAULT))
            val signedString = "${name}&${fingerprintPart}&${expirationTimestampInSeconds}"
            return SignedData(data = signedString.toByteArray(Charsets.UTF_8), signature = signature)
        }
    }

}