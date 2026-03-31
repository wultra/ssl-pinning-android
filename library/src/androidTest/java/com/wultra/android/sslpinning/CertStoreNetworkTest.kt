/*
 * Copyright 2026 Wultra s.r.o.
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

import android.annotation.SuppressLint
import android.util.Base64
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.wultra.android.sslpinning.integration.DefaultCryptoProvider
import com.wultra.android.sslpinning.integration.DefaultSecureDataStore
import com.wultra.android.sslpinning.service.WultraDebug
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.net.HttpURLConnection
import java.net.URL
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLHandshakeException
import javax.net.ssl.X509TrustManager

/**
 * Integration test that validates real communication with the Mobile Utility Server.
 *
 * Requires the following instrumentation arguments:
 * - `test.sslPinning.baseUrl` — base URL of the MUS instance (e.g. `https://mus.example.com`)
 * - `test.sslPinning.appName` — application name registered in MUS
 * - `test.sslPinning.adminLogin` — admin API username
 * - `test.sslPinning.adminPassword` — admin API password
 * - `test.sslPinning.urlToPin` — URL to make pinned HTTPS requests against
 */
@RunWith(AndroidJUnit4::class)
class CertStoreNetworkTest {

    private lateinit var baseUrl: String
    private lateinit var appName: String
    private lateinit var adminLogin: String
    private lateinit var adminPassword: String
    private lateinit var urlToPin: URL
    private lateinit var pubKey: ByteArray
    private lateinit var certStore: CertStore

    val appContext get() = InstrumentationRegistry.getInstrumentation().targetContext

    private data class PublicKeyResponse(var publicKey: String)
    private data class AddCertResponse(var name: String? = null)

    @Before
    fun setUp() {
        WultraDebug.loggingLevel = WultraDebug.WultraLoggingLevel.DEBUG
        val args = InstrumentationRegistry.getArguments()
        baseUrl = args.getString("test.sslPinning.baseUrl")
            ?: throw IllegalArgumentException("Missing test.sslPinning.baseUrl")
        appName = args.getString("test.sslPinning.appName")
            ?: throw IllegalArgumentException("Missing test.sslPinning.appName")
        adminLogin = args.getString("test.sslPinning.adminLogin")
            ?: throw IllegalArgumentException("Missing test.sslPinning.adminLogin")
        adminPassword = args.getString("test.sslPinning.adminPassword")
            ?: throw IllegalArgumentException("Missing test.sslPinning.adminPassword")
        val urlToPinString = args.getString("test.sslPinning.urlToPin")
            ?: throw IllegalArgumentException("Missing test.sslPinning.urlToPin")
        urlToPin = URL(urlToPinString)

        pubKey = getPublicKeyFromServer()

        val config = CertStoreConfiguration.Builder(
            URL("$baseUrl/app/init?appName=$appName"),
            pubKey
        ).useChallenge(true).build()

        certStore = CertStore(
            config,
            DefaultCryptoProvider(),
            DefaultSecureDataStore(appContext, UUID.randomUUID().toString())
        )

        api_clearCertificates()
    }

    // MARK: - Helpers

    private val hostToPin: String
        get() = urlToPin.host ?: fail("Failed to get host from URL to pin").let { "" }

    private val adminCredsBase64: String
        get() = Base64.encodeToString(
            "$adminLogin:$adminPassword".toByteArray(Charsets.UTF_8),
            Base64.NO_WRAP
        )

    private fun appUrl(endpointPath: String) = URL("$baseUrl/app$endpointPath")
    private fun adminUrl(endpointPath: String) = URL("$baseUrl/admin$endpointPath")

    private fun getPublicKeyFromServer(): ByteArray {
        val url = appUrl("/init/public-key?appName=$appName")
        val responseString = url.readText(Charsets.UTF_8)
        val responseObject = CertStore.GSON.fromJson(responseString, PublicKeyResponse::class.java)
        return Base64.decode(responseObject.publicKey, Base64.NO_WRAP)
    }

    // MARK: - API MUS Certificate management

    /**
     * Removes all stored certificates for the [urlToPin] domain via the admin API.
     * Silently succeeds if the domain has no certificates yet (404 is acceptable).
     */
    fun api_clearCertificates() {
        println("Clearing certificates for: $hostToPin")
        val url = URL("${adminUrl("/apps/$appName/domains")}?domain=$hostToPin")
        val connection = url.openConnection() as HttpURLConnection
        connection.requestMethod = "DELETE"
        connection.setRequestProperty("authorization", "Basic $adminCredsBase64")
        try {
            connection.connect()
            val code = connection.responseCode
            println("Clear certificates response: $code")
        } finally {
            connection.disconnect()
        }
    }

    /**
     * Downloads the real certificate from [urlToPin] and registers it in the MUS via the auto-registration endpoint.
     */
    fun api_updateCertificate() {
        println("Updating certificate for: $hostToPin")
        val url = adminUrl("/apps/$appName/certificates/auto")
        val body = """{"domain":"$hostToPin"}"""
        val connection = url.openConnection() as HttpURLConnection
        connection.requestMethod = "POST"
        connection.doOutput = true
        connection.setRequestProperty("Content-Type", "application/json")
        connection.setRequestProperty("authorization", "Basic $adminCredsBase64")
        try {
            connection.outputStream.write(body.toByteArray(Charsets.UTF_8))
            connection.connect()
            val code = connection.responseCode
            println("Update certificate response: $code")
            if (code != 200 && code != 201) {
                fail("api_updateCertificate failed with HTTP $code")
            }
        } finally {
            connection.disconnect()
        }
    }

    /**
     * Submits a PEM-encoded certificate for the given domain and depth via the admin API.
     */
    fun api_addCertificatePEM(pem: String, domain: String, depth: Int) {
        println("Adding PEM certificate for: $domain at depth: $depth")
        val url = adminUrl("/apps/$appName/certificates/pem")
        val body = """{"pem":"${pem.replace("\n", "\\n")}","domain":"$domain","depth":$depth}"""
        val connection = url.openConnection() as HttpURLConnection
        connection.requestMethod = "POST"
        connection.doOutput = true
        connection.setRequestProperty("Content-Type", "application/json")
        connection.setRequestProperty("authorization", "Basic $adminCredsBase64")
        try {
            connection.outputStream.write(body.toByteArray(Charsets.UTF_8))
            connection.connect()
            val code = connection.responseCode
            println("Add PEM certificate response: $code")
            if (code != 200 && code != 201) {
                fail("api_addCertificatePEM failed with HTTP $code for $domain@$depth")
            }
        } finally {
            connection.disconnect()
        }
    }

    /**
     * Configures SSL pinning bypass for the listed domains via the admin API.
     * Pass an empty list to clear all bypass entries and re-enable pinning for all domains.
     */
    fun api_setDomainsConfigBypass(domains: List<String>) {
        println("Setting pinning bypass domains: $domains")
        val url = adminUrl("/apps/$appName/pinning-bypass-domains")
        val body = "[${domains.joinToString(",") { "\"$it\"" }}]"
        val connection = url.openConnection() as HttpURLConnection
        connection.requestMethod = "PUT"
        connection.doOutput = true
        connection.setRequestProperty("Content-Type", "application/json")
        connection.setRequestProperty("authorization", "Basic $adminCredsBase64")
        try {
            connection.outputStream.write(body.toByteArray(Charsets.UTF_8))
            connection.connect()
            val code = connection.responseCode
            println("Set bypass domains response: $code")
            if (code != 200) {
                fail("api_setDomainsConfigBypass failed with HTTP $code")
            }
        } finally {
            connection.disconnect()
        }
    }

    /**
     * Connects to the given URL and extracts the certificate at the given TLS chain depth as a PEM string.
     * Returns null if the connection fails or the depth is out of range.
     */
    fun fetchCertPEM(url: URL, depth: Int): String? {
        println("Fetching certificate PEM for URL: $url and depth: $depth")
        var certPEM: String? = null
        val latch = CountDownLatch(1)

        val trustManager = object : X509TrustManager {
            @SuppressLint("TrustAllX509TrustManager")
            override fun checkClientTrusted(chain: Array<out X509Certificate>, authType: String) {}

            override fun checkServerTrusted(chain: Array<out X509Certificate>, authType: String) {
                if (depth >= 0 && depth < chain.size) {
                    val derData = chain[depth].encoded
                    val base64 = android.util.Base64.encodeToString(derData, android.util.Base64.DEFAULT)
                    certPEM = "-----BEGIN CERTIFICATE-----\n$base64-----END CERTIFICATE-----"
                }
                latch.countDown()
                // allow the connection to proceed
            }

            override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
        }

        try {
            val sslContext = SSLContext.getInstance("TLS")
            sslContext.init(null, arrayOf(trustManager), null)
            val conn = url.openConnection() as HttpsURLConnection
            conn.sslSocketFactory = sslContext.socketFactory
            conn.connect()
            latch.await(10, TimeUnit.SECONDS)
            conn.disconnect()
        } catch (e: Exception) {
            println("fetchCertPEM error: $e")
        }
        return certPEM
    }

    /**
     * Performs a CertStore update and asserts the result is OK.
     */
    private fun performUpdate() {
        val latch = CountDownLatch(1)
        var updateResult: UpdateResult? = null
        certStore.update(UpdateMode.FORCED, object : UpdateObserver {
            override fun onUpdateStarted(type: UpdateType) {}
            override fun onUpdateFinished(type: UpdateType, result: UpdateResult) {
                updateResult = result
                latch.countDown()
            }
        })
        assertTrue(latch.await(30, TimeUnit.SECONDS))
        assertEquals(UpdateResult.OK, updateResult)
    }

    /**
     * Creates an SSL context using a trust manager that calls [certStore.validateCertificateChain]
     * at a given depth. Returns the SSL context and a latch to wait for the validation.
     */
    private fun createDepthTrustManager(depth: Int, onValidation: (ValidationResult) -> Unit): SSLContext {
        val trustManager = object : X509TrustManager {
            @SuppressLint("TrustAllX509TrustManager")
            override fun checkClientTrusted(chain: Array<out X509Certificate>, authType: String) {}

            override fun checkServerTrusted(chain: Array<out X509Certificate>, authType: String) {
                @Suppress("UNCHECKED_CAST")
                val result = certStore.validateCertificateChain(chain as Array<X509Certificate>, depth)
                onValidation(result)
                if (result != ValidationResult.TRUSTED) {
                    throw CertificateException("WultraSSLPinning rejected certificate chain at depth $depth: $result")
                }
            }

            override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
        }
        val sslContext = SSLContext.getInstance("TLS")
        sslContext.init(null, arrayOf(trustManager), null)
        return sslContext
    }

    private fun performRequest(url: URL, sslContext: SSLContext): Boolean {
        return try {
            val conn = url.openConnection() as HttpsURLConnection
            conn.sslSocketFactory = sslContext.socketFactory
            conn.connect()
            val code = conn.responseCode
            conn.disconnect()
            code in 200..299
        } catch (e: SSLHandshakeException) {
            println("SSL handshake failed: $e")
            false
        } catch (e: Exception) {
            println("Request failed: $e")
            false
        }
    }

    // MARK: - Tests

    /**
     * Tests that depth-specific pinning works on a real-world TLS connection.
     *
     * The test registers the leaf certificate (depth 0) via the auto endpoint and
     * the intermediate certificate (depth 1) extracted live from the TLS chain.
     * It then verifies that a real HTTPS request succeeds when validated at both depths.
     */
    @Test
    fun testRealCertificateWithDepth() {
        // Register leaf certificate (depth 0)
        api_updateCertificate()

        // Extract intermediate certificate (depth 1) from the live TLS chain and register it
        val intermediatePEM = fetchCertPEM(urlToPin, 1)
            ?: return fail("Failed to extract intermediate certificate (depth 1) from TLS chain of $hostToPin")
        api_addCertificatePEM(intermediatePEM, hostToPin, 1)

        // Update certificates from MUS
        performUpdate()

        // Validate at depth 0 (leaf certificate)
        var depth0Result: ValidationResult? = null
        val sslContextDepth0 = createDepthTrustManager(0) { depth0Result = it }
        val resultDepth0 = performRequest(urlToPin, sslContextDepth0)
        assertNotNull(depth0Result)
        assertEquals("Expected leaf certificate (depth 0) to be trusted", ValidationResult.TRUSTED, depth0Result)
        assertEquals("Expected request to succeed at depth 0", true, resultDepth0)

        // Validate at depth 1 (intermediate certificate)
        var depth1Result: ValidationResult? = null
        val sslContextDepth1 = createDepthTrustManager(1) { depth1Result = it }
        val resultDepth1 = performRequest(urlToPin, sslContextDepth1)
        assertNotNull(depth1Result)
        assertEquals("Expected intermediate certificate (depth 1) to be trusted", ValidationResult.TRUSTED, depth1Result)
        assertEquals("Expected request to succeed at depth 1", true, resultDepth1)
    }

    /**
     * Tests that DomainsConfig SSL pinning bypass works on a real-world TLS connection.
     *
     * The test registers the leaf certificate for the target host, then configures it as a bypass
     * domain. While the bypass is active, [CertStore.validateCertificateChain] must return TRUSTED
     * regardless of what certificate is presented. After clearing the bypass, the test confirms
     * that normal fingerprint-based pinning is restored.
     */
    @Test
    fun testRealCertificateWithDomainsConfigBypass() {
        // Ensure a clean bypass state
        api_setDomainsConfigBypass(emptyList())

        // Register the leaf certificate so the domain is known to the server
        api_updateCertificate()

        // Configure SSL pinning bypass for the target host
        api_setDomainsConfigBypass(listOf(hostToPin))

        // Update certificates from MUS (picks up the new domainsConfig)
        performUpdate()

        // With bypass active, validation must return TRUSTED regardless of the certificate
        var bypassResult: ValidationResult? = null
        val bypassSslContext = createDepthTrustManager(0) { bypassResult = it }
        val bypassRequestResult = performRequest(urlToPin, bypassSslContext)
        assertNotNull(bypassResult)
        assertEquals("Expected TRUSTED with bypass active", ValidationResult.TRUSTED, bypassResult)
        assertEquals("Expected request to succeed with bypass", true, bypassRequestResult)

        // Clear bypass and update again
        api_setDomainsConfigBypass(emptyList())
        performUpdate()

        // Without bypass, normal fingerprint-based pinning should apply
        var restoredResult: ValidationResult? = null
        val restoredSslContext = createDepthTrustManager(0) { restoredResult = it }
        val restoredRequestResult = performRequest(urlToPin, restoredSslContext)
        assertNotNull(restoredResult)
        assertEquals("Expected TRUSTED after bypass cleared (valid cert registered)", ValidationResult.TRUSTED, restoredResult)
        assertEquals("Expected request to succeed after bypass cleared", true, restoredRequestResult)
    }
}
