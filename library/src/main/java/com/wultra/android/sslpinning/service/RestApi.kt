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
import java.lang.Exception
import java.net.HttpURLConnection
import java.net.URL

/**
 * Handling of network communication with the server.
 * Used internally in [CertStore].
 *
 * @property baseUrl URL of the remote server.
 * @author Tomas Kypta, tomas.kypta@wultra.com
 */
class RestApi(private val baseUrl: URL) : RemoteDataProvider {

    companion object {
        const val CONTENT_TYPE = "application/json"
    }

    init {

    }

    /**
     * Exception denoting that the server request failed.
     */
    class NetworkException : Exception()

    /**
     * Perform REST request to get fingerprints from the remote server.
     *
     * @return Bytes as recieved from the remote server. Typically containing data in JSON format.
     */
    @WorkerThread
    override fun getFingerprints(): ByteArray {
        val connection = baseUrl.openConnection() as HttpURLConnection
        connection.requestMethod = "GET"
        connection.addRequestProperty("Accept", CONTENT_TYPE)
        try {
            connection.connect()
            val responseCode = connection.responseCode
            val responseOk = responseCode / 100 == 2
            if (responseOk) {
                connection.inputStream
                return connection.inputStream.use { it.readBytes() }
            } else {
                throw NetworkException()
            }
        } catch (t: Throwable) {
            WultraDebug.warning("RestAPI: HTTP request failed with error: ${t}")
            throw t
        } finally {
            connection.disconnect()
        }
    }

}