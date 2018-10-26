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

import java.io.Serializable
import java.util.*

/**
 * Data class for holding certificate info necessary for certificate validation.
 *
 * @author Tomas Kypta, tomas.kypta@wultra.com
 */
data class CertificateInfo(val commonName: String,
                           val fingerprint: ByteArray,
                           val expires: Date) : Serializable, Comparable<CertificateInfo> {

    internal constructor(responseEntry: GetFingerprintResponse.Entry) :
            this(commonName = responseEntry.name, fingerprint = responseEntry.fingerprint,
                    expires = responseEntry.expires)

    /**
     * Check if the info is expired.
     */
    internal fun isExpired(date: Date): Boolean {
        return expires.before(date)
    }

    override fun compareTo(other: CertificateInfo): Int {
        if (this.commonName == other.commonName) {
            return -this.expires.compareTo(other.expires)
        }
        return this.commonName.compareTo(other.commonName)
    }
}