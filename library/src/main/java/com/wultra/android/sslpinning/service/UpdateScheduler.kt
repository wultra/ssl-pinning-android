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

package com.wultra.android.sslpinning.service

import com.wultra.android.sslpinning.model.CertificateInfo
import java.util.*
import java.util.concurrent.TimeUnit

/**
 * Helper class for calculatinngn date of the next update.
 *
 * @property periodicUpdateIntervalMillis Defines interval between checks for update of certificate fingerprints
 * @property expirationUpdateThresholdMillis Define time window in milliseconds before a certificate expires
 * @property thresholdMultiplier A constant for calculating closer date when a certificate is going to expire soon.
 * Should be smaller than 1.
 *
 * @author Tomas Kypta, tomas.kypta@wultra.com
 */
internal class UpdateScheduler(private val periodicUpdateIntervalMillis: Long,
                               private val expirationUpdateThresholdMillis: Long,
                               private val thresholdMultiplier: Double) {


    /**
     * Calculates the next date for silent update.
     *
     * @param certificates List of certificates from which the next update is calculated.
     * @param currentDate Date from which to calculate the next update.
     */
    fun scheduleNextUpdate(certificates: Array<CertificateInfo>,
                           currentDate: Date): Date {

        // At first, we will look for expired certificate with closest expiration date.
        // We will also ignore older entries for the same common name. We don't need to update frequently
        // once the replacement certificate is in database.
        val processedCommonNames = mutableSetOf<String>()

        // set nextExpired to approximately +10 years
        var nextExpired = currentDate.time + TimeUnit.DAYS.toMillis(10 * 365)
        for (certificateInfo in certificates) {
            if (processedCommonNames.contains(certificateInfo.commonName)) {
                continue
            }
            processedCommonNames.add(certificateInfo.commonName)
            nextExpired = Math.min(nextExpired, certificateInfo.expires.time)
        }

        var nextExpiredIntervalMillis = nextExpired - currentDate.time
        if (nextExpiredIntervalMillis > 0) {
            if (nextExpiredIntervalMillis < expirationUpdateThresholdMillis) {
                // if we're below the threshold, don't wait for certificate expiration
                // ask server more often for update
                nextExpiredIntervalMillis = Math.round(nextExpiredIntervalMillis * thresholdMultiplier)
            }
        } else {
            // looks like the newest is already expired
            // set the scheduled date to current
            nextExpiredIntervalMillis = 0
        }

        // finally, choose between periodic update
        nextExpiredIntervalMillis = Math.min(nextExpiredIntervalMillis, periodicUpdateIntervalMillis)
        return Date(currentDate.time + nextExpiredIntervalMillis)
    }
}