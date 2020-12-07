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

import android.support.annotation.WorkerThread

/**
 * Abstract remote APIs of SSL pinning library.
 * Defines interface for getting fingerprints from remote server.
 *
 * @author Tomas Kypta, tomas.kypta@wultra.com
 */
interface RemoteDataProvider {

    /**
     * Gets data containing fingerprints from the remote server.
     *
     * Always invoke on a worker thread.
     * @param request Request object
     * @return Response object.
     */
    @WorkerThread
    fun getFingerprints(request: RemoteDataRequest): RemoteDataResponse
}

/**
 * Class contains information required for constructing HTTP request to acquire data
 * from the remote server.
 */
data class RemoteDataRequest(val requestHeaders: Map<String, String>)

/**
 * Class contains response received from the server. Note that response headers contains lowercase
 * header names.
 */
data class RemoteDataResponse(
        /**
         * HTTP response code.
         */
        val responseCode: Int,
        /**
         * Response headers.
         */
        val responseHeaders: Map<String, String>,
        /**
         * Received data.
         */
        val data: ByteArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as RemoteDataResponse

        if (responseCode != other.responseCode) return false
        if (responseHeaders != other.responseHeaders) return false
        if (!data.contentEquals(other.data)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = responseCode
        result = 31 * result + responseHeaders.hashCode()
        result = 31 * result + data.contentHashCode()
        return result
    }
}