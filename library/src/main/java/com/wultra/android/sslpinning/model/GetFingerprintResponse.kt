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

/**
 * @author Tomas Kypta, tomas.kypta@wultra.com
 */
data class GetFingerprintResponse(val fingerprints: Array<Entry>) {

    data class Entry(val name: String,
                     val fingerprint: ByteArray,
                     val expires: Date,
                     val signature: ByteArray) {

        internal fun dataForSignature(): SignedData? {
            val expirationTimestamp = expires.time
            val signedString = "${name}&${Base64.encode(fingerprint, Base64.DEFAULT)}&${expirationTimestamp}"
            return SignedData(data = signedString.toByteArray(Charsets.UTF_8), signature = signature)
        }
    }

}