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

import android.os.Handler
import com.wultra.android.sslpinning.model.GetFingerprintResponse
import org.junit.Assert
import java.io.ByteArrayInputStream
import java.io.File
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Date
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import javax.net.ssl.HttpsURLConnection

/**
 * @author Tomas Kypta, tomas.kypta@wultra.com
 */
class TestUtils {

    companion object {

        @Throws(Exception::class)
        fun githubCert(): X509Certificate {
            return getCertificateFromBase64Data(readFile("cert.pem"))
        }

        fun testPubKey() = readFile("pub.key").decodeToString().replace("\n", "")

        fun validFingerprintJsonResponse() = """{ "fingerprints": [ ${readFile("valid_github.json").decodeToString()} ] }""".toByteArray()

        fun readFile(fileName: String): ByteArray {
            val jsonFile = File(TestUtils::class.java.classLoader!!.getResource(fileName).toURI())
            return jsonFile.readBytes()
        }

        @Throws(Exception::class)
        fun getCertificateFromBase64Data(data: ByteArray): X509Certificate {
            val certFactory = CertificateFactory.getInstance("X.509")
            val inputStream = ByteArrayInputStream(data)
            return certFactory.generateCertificate(inputStream) as X509Certificate
        }

        @JvmStatic
        @Throws(IOException::class)
        fun getCertificateFromUrl(urlString: String?): X509Certificate {
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

        @JvmStatic
        fun getCertStoreConfiguration(
            expiration: Date,
            expectedCommonNames: Array<String>?,
            serviceUrl: URL,
            publicKey: ByteArray,
            fallback: Array<GetFingerprintResponse.Entry>?
        ): CertStoreConfiguration {
            val builder = CertStoreConfiguration.Builder(
                serviceUrl, publicKey
            )
                .identifier(null)
                .expectedCommonNames(expectedCommonNames)
                .fallbackCertificates(fallback)
            return builder.build()
        }

        @JvmStatic
        @Throws(Exception::class)
        fun assignHandler(certStore: CertStore?, handler: Handler?) {
            val handlerField = CertStore::class.java.getDeclaredField("mainThreadHandler")
            handlerField.isAccessible = true
            handlerField[certStore] = handler
        }

        @Throws(Exception::class)
        fun updateAndCheck(
            store: CertStore,
            updateMode: UpdateMode,
            expectedUpdateResult: UpdateResult?
        ): UpdateResult {
            val initLatch = CountDownLatch(1)
            val latch = CountDownLatch(1)
            val updateWrapper = UpdateWrapper()
            store.update(updateMode, object : UpdateObserver {
                override fun onUpdateStarted(type: UpdateType) {
                    updateWrapper.updateType = type
                    initLatch.countDown()
                }

                override fun onUpdateFinished(type: UpdateType, result: UpdateResult) {
                    updateWrapper.updateResult = result
                    latch.countDown()
                }
            })
            initLatch.await(500, TimeUnit.MILLISECONDS)
            Assert.assertNotNull(updateWrapper.updateType)
            if (updateWrapper.updateType!!.isPerformingUpdate) {
                Assert.assertTrue(latch.await(15, TimeUnit.SECONDS))
            }
            if (expectedUpdateResult != null) {
                Assert.assertEquals(expectedUpdateResult, updateWrapper.updateResult)
            }
            return updateWrapper.updateResult!!
        }
    }
}
