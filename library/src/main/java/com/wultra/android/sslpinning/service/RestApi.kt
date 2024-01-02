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

import androidx.annotation.WorkerThread
import com.wultra.android.sslpinning.SslValidationStrategy
import java.io.IOException
import java.lang.Exception
import java.net.HttpURLConnection
import java.net.URL
import java.nio.charset.Charset
import java.util.*
import javax.net.ssl.HttpsURLConnection

/**
 * Handling of network communication with the server.
 * Used internally in [com.wultra.android.sslpinning.CertStore].
 *
 * @property baseUrl URL of the remote server.
 * @author Tomas Kypta, tomas.kypta@wultra.com
 */
class RestApi(
        private val baseUrl: URL,
        private val sslValidationStrategy: SslValidationStrategy?) : RemoteDataProvider {

    companion object {
        const val CONTENT_TYPE = "application/json"
    }

    init {

    }

    /**
     * Exception denoting that the server request failed.
     */
    class NetworkException(val response: RemoteDataResponse) : Exception()

    /**
     * Perform REST request to get fingerprints from the remote server.
     *
     * @return Bytes as received from the remote server. Typically containing data in JSON format.
     */
    @WorkerThread
    override fun getFingerprints(request: RemoteDataRequest): RemoteDataResponse {
        val connection = baseUrl.openConnection() as HttpURLConnection
        connection.requestMethod = "GET"
        connection.addRequestProperty("Accept", CONTENT_TYPE)
        request.requestHeaders.forEach { header ->
            connection.addRequestProperty(header.key, header.value)
        }
        if (sslValidationStrategy != null) {
            val secureConnection = connection as? HttpsURLConnection
            if (secureConnection != null) {
                val socketFactory = sslValidationStrategy.sslSocketFactory()
                val hosntameVerifier = sslValidationStrategy.hostnameVerifier()
                if (socketFactory != null) {
                    secureConnection.sslSocketFactory = socketFactory
                }
                if (hosntameVerifier != null) {
                    secureConnection.hostnameVerifier = hosntameVerifier
                }
            }
        }
        logRequest(connection)
        try {
            connection.connect()
            val responseCode = connection.responseCode
            val responseOk = responseCode / 100 == 2
            val inputStream = if (responseOk) connection.inputStream else connection.errorStream
            val data = inputStream.use { it.readBytes() }
            val headers = mutableMapOf<String, String>()
            connection.headerFields.keys.forEach { headerName ->
                if (headerName != null) {
                    val headerValue = connection.getHeaderField(headerName)
                    if (headerValue != null) {
                        headers[headerName.lowercase(Locale.getDefault())] = headerValue
                    }
                }
            }
            val responseData = RemoteDataResponse(responseCode, headers, data)
            if (!responseOk) {
                throw NetworkException(responseData)
            }
            logResponse(connection, data, null)
            return responseData
        } catch (e: NetworkException) {
            logResponse(connection, e.response.data, null)
            WultraDebug.warning("RestAPI: HTTP request failed with response code ${e.response.responseCode}")
            throw e
        } catch (t: Throwable) {
            logResponse(connection, null, t)
            WultraDebug.warning("RestAPI: HTTP request failed with error: $t")
            throw t
        } finally {
            connection.disconnect()
        }
    }

    /**
     * Dump request data into debug log.
     *
     * @param connection Connection object.
     */
    private fun logRequest(connection: HttpURLConnection) {
        if (WultraDebug.loggingLevel == WultraDebug.WultraLoggingLevel.DEBUG) {
            val url = connection.url
            val method = connection.requestMethod
            var message = "HTTP ${method} request: -> ${url}"
            if (connection.requestProperties != null) {
                message += "\n- Headers: ${connection.requestProperties}"
            }
            WultraDebug.info(message)
        }
    }

    /**
     * Dump response data into debug log.
     *
     * @param connection Connection object.
     * @param data Data received from the server.
     * @param error Error produced during the connection.
     */
    private fun logResponse(connection: HttpURLConnection, data: ByteArray?, error: Throwable?) {
        if (WultraDebug.loggingLevel == WultraDebug.WultraLoggingLevel.DEBUG) {
            val url = connection.url
            val method = connection.requestMethod
            val responseCode = try {
                connection.responseCode
            } catch (e: IOException) {
                0
            }
            var message = "HTTP ${method} response: ${responseCode} <- ${url}"
            if (connection.headerFields != null) {
                message += "\n- Headers: ${connection.headerFields}"
            }
            if (data != null) {
                val dataString = data.toString(Charsets.UTF_8)
                message += "\n- Data: ${dataString}"
            }
            if (error != null) {
                message += "\n- Error: ${error}"
            }
            WultraDebug.info(message)
        }
    }
}
