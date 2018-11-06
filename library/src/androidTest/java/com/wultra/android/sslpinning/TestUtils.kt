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
import com.google.gson.GsonBuilder
import com.wultra.android.sslpinning.service.RemoteDataProvider
import com.wultra.android.sslpinning.util.ByteArrayTypeAdapter
import com.wultra.android.sslpinning.util.DateTypeAdapter
import java.net.HttpURLConnection
import java.net.URL
import java.security.cert.X509Certificate
import java.util.*
import javax.net.ssl.HttpsURLConnection

/**
 * Utility properties and functions for instrumentation tests.
 *
 * @author Tomas Kypta, tomas.kypta@wultra.com
 */
val remoteDataProvider: RemoteDataProvider = object : RemoteDataProvider {
    override fun getFingerprints(): kotlin.ByteArray {
        return jsonData.toByteArray(Charsets.UTF_8)
    }
}

val jsonData = """
{
  "fingerprints": [
    {
      "name" : "github.com",
      "fingerprint" : "MRFQDEpmASza4zPsP8ocnd5FyVREDn7kE3Fr/zZjwHQ=",
      "expires" : 1591185600,
      "signature" : "MEUCIQD8nGyux9GM8u3XCrRiuJj/N2eEuB0oiHzTEpGyy2gE9gIgYIRfyed6ykDzZbK1ougq1SoRW8UBe5q3VmWihHuL2JY="
    }
  ]
}
"""

val url = URL("https://gist.githubusercontent.com/hvge/7c5a3f9ac50332a52aa974d90ea2408c/raw/c5b021db0fcd40b1262ab513bf375e4641834925/ssl-pinning-signatures.json")
val publicKey = "BC3kV9OIDnMuVoCdDR9nEA/JidJLTTDLuSA2TSZsGgODSshfbZg31MS90WC/HdbU/A5WL5GmyDkE/iks6INv+XE="
fun getPublicKeyBytes(): ByteArray {
    return Base64.decode(publicKey, android.util.Base64.NO_WRAP)
}

val GSON = GsonBuilder()
        .registerTypeAdapter(ByteArray::class.java, ByteArrayTypeAdapter())
        .registerTypeAdapter(Date::class.java, DateTypeAdapter())
        .create()

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