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

import java.util.*

/**
 * Data class for stored data - list of certificates and next update date.
 *
 * @author Tomas Kypta, tomas.kypta@wultra.com
 */
internal data class CachedData(var certificates: Array<CertificateInfo>,
                               var nextUpdate: Date) {

    internal fun numberOfValidCertificates(date: Date): Int {
        var result = 0
        for (cert in certificates) {
            if (!cert.isExpired(date)) {
                result += 1
            }
        }
        return result
    }

    /**
     * Sorts certificates stored in CachedData structure. Entries are alphabetically sorted
     * by the common name. For entries with the same common name, the entries with expiration
     * in more distant future will be first. This order allows to have more recent certs at first positions,
     * so we can more easily calculate when the next silent update will be scheduled.
     */
    internal fun sort() {
        certificates.sort()
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as CachedData

        if (!certificates.contentEquals(other.certificates)) return false
        if (nextUpdate != other.nextUpdate) return false

        return true
    }

    override fun hashCode(): Int {
        var result = certificates.contentHashCode()
        result = 31 * result + nextUpdate.hashCode()
        return result
    }
}

