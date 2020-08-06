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

import android.content.Context
import android.support.test.InstrumentationRegistry
import android.util.Base64
import com.google.gson.GsonBuilder
import com.wultra.android.sslpinning.integration.powerauth.PowerAuthSecureDataStore
import com.wultra.android.sslpinning.service.RemoteDataProvider
import com.wultra.android.sslpinning.util.ByteArrayTypeAdapter
import com.wultra.android.sslpinning.util.DateTypeAdapter
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import java.net.HttpURLConnection
import java.net.URL
import java.security.cert.X509Certificate
import java.util.*
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import javax.net.ssl.HttpsURLConnection

/**
 * Utility properties and functions for instrumentation tests.
 *
 * @author Tomas Kypta, tomas.kypta@wultra.com
 */
val remoteDataProvider = getRemoteDataProvider()
fun getRemoteDataProvider(json: String = jsonData): RemoteDataProvider {
    return object : RemoteDataProvider {
        override fun getFingerprints(): kotlin.ByteArray {
            return json.toByteArray(Charsets.UTF_8)
        }
    }
}

const val jsonData = """
{
  "fingerprints": [
    {
      "name" : "github.com",
      "fingerprint" : "trmmrz6GbL4OajB+fdoXOzcrLTrD8GrxX5dxh3OEgAg=",
      "expires" : 1652184000,
      "signature" : "MEUCIQCs1y/nyrKh4+2DIuX/PufUYiaVUdt2FBZQg6rBeZ/r4QIgNlT4owBwJ1ThrDsE0SwGipTNI74vP1vNyLNEwuXY4lE="
    }
  ]
}
"""

const val jsonDataFingerprintsEmpty = "{\"fingerprints\":[]}"
const val jsonDataAllEmpty = "{}"


val url = URL("https://gist.githubusercontent.com/hvge/7c5a3f9ac50332a52aa974d90ea2408c/raw/34866234bbaa3350dc0ddc5680a65a6f4e7c549e/ssl-pinning-signatures.json")
const val publicKey = "BC3kV9OIDnMuVoCdDR9nEA/JidJLTTDLuSA2TSZsGgODSshfbZg31MS90WC/HdbU/A5WL5GmyDkE/iks6INv+XE="
fun getPublicKeyBytes(): ByteArray {
    return Base64.decode(publicKey, android.util.Base64.NO_WRAP)
}

val GSON = GsonBuilder()
        .registerTypeAdapter(ByteArray::class.java, ByteArrayTypeAdapter())
        .registerTypeAdapter(Date::class.java, DateTypeAdapter())
        .create()!!

fun getCertificateFromUrl(urlString: String): X509Certificate {
    val url = URL(urlString)
    val httpURLConnection = url.openConnection() as HttpURLConnection
    val connection = httpURLConnection as HttpsURLConnection
    try {
        connection.connect()
        val certificates = connection.serverCertificates
        return certificates[0] as X509Certificate
    } finally {
        connection.disconnect()
    }
}

@Throws(Exception::class)
@JvmOverloads
fun updateAndCheck(store: CertStore, updateMode: UpdateMode, expectedUpdateResult: UpdateResult, expectedUpdateType: UpdateType? = null) {
    val initLatch = CountDownLatch(1)
    val latch = CountDownLatch(1)
    val updateResultWrapper = UpdateWrapperInstr()
    val updateStarted = store.update(updateMode, object : UpdateObserver {
        override fun onUpdateStarted(type: UpdateType) {
            updateResultWrapper.updateType = type
            initLatch.countDown()
        }

        override fun onUpdateFinished(type: UpdateType, result: UpdateResult) {
            updateResultWrapper.updateResult = result
            latch.countDown()
        }
    })
    initLatch.await(500, TimeUnit.MILLISECONDS)
    updateResultWrapper.updateType?.isPerformingUpdate?.let {
        assertTrue(latch.await(30, TimeUnit.SECONDS))
    }
    assertEquals(expectedUpdateResult, updateResultWrapper.updateResult)
    expectedUpdateType?.let {
        assertEquals(it, updateResultWrapper.updateType)
    }
}

fun clearStorage() {
    val appContext = InstrumentationRegistry.getTargetContext()
    appContext.getSharedPreferences(PowerAuthSecureDataStore.defaultKeychainIdentifier, Context.MODE_PRIVATE)
            .edit()
            .clear()
            .commit()
}