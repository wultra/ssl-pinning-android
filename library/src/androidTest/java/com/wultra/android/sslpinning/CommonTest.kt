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

package com.wultra.android.sslpinning

import android.util.Base64
import androidx.test.platform.app.InstrumentationRegistry
import com.wultra.android.sslpinning.service.WultraDebug
import org.junit.Before
import java.io.File
import java.net.URL

/**
 * Common instrumentation test setup.
 *
 * @author Tomas Kypta, tomas.kypta@wultra.com
 */
abstract class CommonTest {

    private lateinit var baseUrl: String
    private lateinit var appName: String
    protected lateinit var pubKey: ByteArray
    protected val serviceUrl by lazy { URL("$baseUrl/init?appName=$appName") }

    val appContext = InstrumentationRegistry.getInstrumentation().targetContext

    @Before
    open fun setUp() {
        WultraDebug.loggingLevel = WultraDebug.WultraLoggingLevel.DEBUG
        clearStorage()
        baseUrl = InstrumentationRegistry.getArguments().getString("test.sslPinning.baseUrl") ?: "https://int-mus-dev.wultra.app/app"
        appName = InstrumentationRegistry.getArguments().getString("test.sslPinning.appName") ?: "ssl-pinning-tests"
        pubKey = getPublicKeyFromServer()
    }

    private data class PublicKeyResponse(var publicKey: String)

    private fun getPublicKeyFromServer(): ByteArray {
        val url = URL("$baseUrl/init/public-key?appName=$appName")
        val responseString = url.readText(Charsets.UTF_8)
        val responseObject = GSON.fromJson(responseString, PublicKeyResponse::class.java)
        return Base64.decode(responseObject.publicKey, Base64.NO_WRAP)
    }

    fun validFingerprintJsonResponse() = """{ "fingerprints": [ ${readAssetFile("valid_github.json")} ] }""".toByteArray()

    private fun readAssetFile(fileName: String): String {
        val context = InstrumentationRegistry.getInstrumentation().context
        val inputStream = context.assets.open(fileName)
        return inputStream.bufferedReader().use { it.readText() }
    }
}