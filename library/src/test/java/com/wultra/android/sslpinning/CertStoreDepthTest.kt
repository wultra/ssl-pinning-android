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

import com.wultra.android.sslpinning.model.CachedData
import com.wultra.android.sslpinning.model.CertificateInfo
import com.wultra.android.sslpinning.service.RemoteDataProvider
import com.wultra.android.sslpinning.service.RemoteDataResponse
import io.mockk.every
import io.mockk.mockk
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test
import java.net.URL
import java.util.Base64
import java.util.Date
import java.util.concurrent.TimeUnit

/**
 * Tests for certificate depth functionality: depth-aware fingerprint matching,
 * [CertificateInfo] model depth handling, and depth serialization in [CachedData].
 *
 * Mirrors the iOS `CertStoreTests_Depth` test class.
 */
class CertStoreDepthTest : CommonKotlinTest() {

    // Common test fixtures
    private val commonName1 = "test.example.com"
    private val commonName2 = "other.example.com"
    private val fingerprint1 = ByteArray(32) { 1 }
    private val fingerprint2 = ByteArray(32) { 2 }
    private val fingerprintUnknown = ByteArray(32) { 99 }
    private val validExpiresMs: Long = System.currentTimeMillis() + TimeUnit.DAYS.toMillis(365)

    private val responseGenerator = ResponseGenerator()

    private fun buildCertStore(
        remoteDataProvider: RemoteDataProvider,
        expectedCommonNames: Array<String>? = null
    ): CertStore {
        val publicKeyBytes = Base64.getDecoder().decode(
            "BC3kV9OIDnMuVoCdDR9nEA/JidJLTTDLuSA2TSZsGgODSshfbZg31MS90WC/HdbU/A5WL5GmyDkE/iks6INv+XE="
        )
        val config = TestUtils.getCertStoreConfiguration(
            Date(), expectedCommonNames, URL("https://test"), publicKeyBytes, null
        )
        val store = CertStore(config, cryptoProvider, secureDataStore, remoteDataProvider)
        TestUtils.assignHandler(store, handler)
        return store
    }

    private fun buildRemoteProvider(responseData: ByteArray): RemoteDataProvider {
        val provider: RemoteDataProvider = mockk()
        every { provider.getFingerprints(any()) } answers {
            RemoteDataResponse(200, emptyMap(), responseData)
        }
        return provider
    }

    // -------------------------------------------------------------------------
    // Certificate Depth Tests
    // -------------------------------------------------------------------------

    /**
     * Tests that a leaf-certificate fingerprint (depth 0) is correctly validated when the
     * server responds with an entry that has no explicit depth (backward compat defaults to 0).
     */
    @Test
    fun testCertDepth_BackwardCompatibility_NoDepthDefaultsToLeaf() {
        every { cryptoProvider.ecdsaValidateSignature(any(), any()) } returns true

        val responseData = responseGenerator
            .removeAll()
            .append(commonName = commonName1, fingerprint = fingerprint1)
            .data()

        val store = buildCertStore(buildRemoteProvider(responseData))
        TestUtils.updateAndCheck(store, UpdateMode.FORCED, UpdateResult.OK)

        // depth 0 should match the stored leaf cert
        assertEquals(ValidationResult.TRUSTED, store.validateFingerprint(commonName1, fingerprint1, 0))
        assertEquals(ValidationResult.TRUSTED, store.validateFingerprint(commonName1, fingerprint1))
    }

    /**
     * Tests that a cert entry pinned at depth 1 (intermediate) is only trusted at depth 1,
     * not at depth 0 or depth 2.
     */
    @Test
    fun testCertDepth_IntermediateCert_MatchesOnlyAtCorrectDepth() {
        every { cryptoProvider.ecdsaValidateSignature(any(), any()) } returns true

        val responseData = responseGenerator
            .removeAll()
            .append(commonName = commonName1, fingerprint = fingerprint1, depth = 1)
            .data()

        val store = buildCertStore(buildRemoteProvider(responseData))
        TestUtils.updateAndCheck(store, UpdateMode.FORCED, UpdateResult.OK)

        // depth 1 — should match
        assertEquals(ValidationResult.TRUSTED, store.validateFingerprint(commonName1, fingerprint1, 1))
        // depth 0 — wrong depth, same CN is known at depth 1 only → empty (matchAttempts = 0 at depth 0)
        assertEquals(ValidationResult.EMPTY, store.validateFingerprint(commonName1, fingerprint1, 0))
        // depth 2 — also wrong depth → empty
        assertEquals(ValidationResult.EMPTY, store.validateFingerprint(commonName1, fingerprint1, 2))
    }

    /**
     * Tests that wrong fingerprint at the correct depth returns untrusted.
     */
    @Test
    fun testCertDepth_WrongFingerprintAtCorrectDepth_ReturnsUntrusted() {
        every { cryptoProvider.ecdsaValidateSignature(any(), any()) } returns true

        val responseData = responseGenerator
            .removeAll()
            .append(commonName = commonName1, fingerprint = fingerprint1, depth = 1)
            .data()

        val store = buildCertStore(buildRemoteProvider(responseData))
        TestUtils.updateAndCheck(store, UpdateMode.FORCED, UpdateResult.OK)

        // Known CN at depth 1, but wrong fingerprint → untrusted
        assertEquals(ValidationResult.UNTRUSTED, store.validateFingerprint(commonName1, fingerprintUnknown, 1))
    }

    /**
     * Tests that multiple entries for the same CN at different depths are all correctly stored
     * and validated independently.
     */
    @Test
    fun testCertDepth_MultipleDepthsForSameCN() {
        every { cryptoProvider.ecdsaValidateSignature(any(), any()) } returns true

        val responseData = responseGenerator
            .removeAll()
            .append(commonName = commonName1, fingerprint = fingerprint1, depth = 0)
            .append(commonName = commonName1, fingerprint = fingerprint2, depth = 1)
            .data()

        val store = buildCertStore(buildRemoteProvider(responseData))
        TestUtils.updateAndCheck(store, UpdateMode.FORCED, UpdateResult.OK)

        // Each depth matches its own fingerprint
        assertEquals(ValidationResult.TRUSTED, store.validateFingerprint(commonName1, fingerprint1, 0))
        assertEquals(ValidationResult.TRUSTED, store.validateFingerprint(commonName1, fingerprint2, 1))

        // Cross-depth: fingerprint1 at depth 1 → wrong fingerprint at that depth → untrusted
        assertEquals(ValidationResult.UNTRUSTED, store.validateFingerprint(commonName1, fingerprint1, 1))
        // Cross-depth: fingerprint2 at depth 0 → wrong fingerprint at that depth → untrusted
        assertEquals(ValidationResult.UNTRUSTED, store.validateFingerprint(commonName1, fingerprint2, 0))
    }

    /**
     * Tests that the no-argument [CertStore.validateFingerprint] and
     * [CertStore.validateFingerprint] with depth=0 are equivalent.
     */
    @Test
    fun testCertDepth_DefaultValidateEquivalentToDepthZero() {
        every { cryptoProvider.ecdsaValidateSignature(any(), any()) } returns true

        val responseData = responseGenerator
            .removeAll()
            .append(commonName = commonName1, fingerprint = fingerprint1, depth = 0)
            .data()

        val store = buildCertStore(buildRemoteProvider(responseData))
        TestUtils.updateAndCheck(store, UpdateMode.FORCED, UpdateResult.OK)

        val resultDefault = store.validateFingerprint(commonName1, fingerprint1)
        val resultDepth0 = store.validateFingerprint(commonName1, fingerprint1, 0)
        assertEquals(resultDefault, resultDepth0)
        assertEquals(ValidationResult.TRUSTED, resultDefault)
    }

    /**
     * Tests that a depth-1 entry does not interfere with the legacy depth-less validate path.
     */
    @Test
    fun testCertDepth_DepthOneCertDoesNotAffectLegacyValidate() {
        every { cryptoProvider.ecdsaValidateSignature(any(), any()) } returns true

        val responseData = responseGenerator
            .removeAll()
            .append(commonName = commonName1, fingerprint = fingerprint1, depth = 1)
            .data()

        val store = buildCertStore(buildRemoteProvider(responseData))
        TestUtils.updateAndCheck(store, UpdateMode.FORCED, UpdateResult.OK)

        // Legacy validateFingerprint (depth 0) — no matching depth-0 cert → empty
        assertEquals(ValidationResult.EMPTY, store.validateFingerprint(commonName1, fingerprint1))
    }

    // -------------------------------------------------------------------------
    // CertificateInfo model tests
    // -------------------------------------------------------------------------

    /**
     * Tests that [CertificateInfo] initialised from a response entry without a depth defaults to 0.
     */
    @Test
    fun testCertificateInfo_DepthDefaultsToZeroWhenAbsent() {
        val entry = com.wultra.android.sslpinning.model.GetFingerprintResponse.Entry(
            name = commonName1,
            fingerprint = fingerprint1,
            expires = Date(validExpiresMs),
            signature = null,
            depth = null
        )
        val info = CertificateInfo(entry)
        assertEquals(0, info.depth)
    }

    /**
     * Tests that [CertificateInfo] initialised from a response entry with depth 2 stores depth 2.
     */
    @Test
    fun testCertificateInfo_DepthIsPreservedFromResponseEntry() {
        val entry = com.wultra.android.sslpinning.model.GetFingerprintResponse.Entry(
            name = commonName1,
            fingerprint = fingerprint1,
            expires = Date(validExpiresMs),
            signature = null,
            depth = 2
        )
        val info = CertificateInfo(entry)
        assertEquals(2, info.depth)
    }

    /**
     * Tests that the default [CertificateInfo] constructor (without depth) defaults depth to 0.
     */
    @Test
    fun testCertificateInfo_DefaultConstructorDepthIsZero() {
        val info = CertificateInfo(commonName1, fingerprint1, Date(validExpiresMs))
        assertEquals(0, info.depth)
    }

    /**
     * Tests [CertificateInfo] equality: two entries with identical fields but different depths are not equal.
     */
    @Test
    fun testCertificateInfo_EqualityConsidersDepth() {
        val expires = Date(validExpiresMs)
        val infoDepth0 = CertificateInfo(commonName1, fingerprint1, expires, 0)
        val infoDepth1 = CertificateInfo(commonName1, fingerprint1, expires, 1)
        val infoDepth0Copy = CertificateInfo(commonName1, fingerprint1, expires, 0)

        assertEquals(false, infoDepth0 == infoDepth1)
        assertEquals(true, infoDepth0 == infoDepth0Copy)
    }

    // -------------------------------------------------------------------------
    // CachedData serialization
    // -------------------------------------------------------------------------

    /**
     * Tests that [CachedData] with depth values round-trips correctly through GSON.
     */
    @Test
    fun testCachedData_DepthValuesRoundTrip() {
        val expires = Date(validExpiresMs)
        val certs = arrayOf(
            CertificateInfo(commonName1, fingerprint1, expires, 0),
            CertificateInfo(commonName1, fingerprint2, expires, 1),
            CertificateInfo(commonName2, fingerprint2, expires, 2)
        )
        val cached = CachedData(certs, expires, null)

        val json = CertStore.GSON.toJson(cached)
        val decoded = CertStore.GSON.fromJson(json, CachedData::class.java)

        assertNotNull(decoded)
        assertEquals(certs.size, decoded.certificates.size)
        assertEquals(0, decoded.certificates[0].depth)
        assertEquals(1, decoded.certificates[1].depth)
        assertEquals(2, decoded.certificates[2].depth)
        assertNull(decoded.domainsConfig)
    }

    /**
     * Tests that legacy [CachedData] JSON without the "depth" key in certificates
     * deserialises with depth defaulting to 0 (GSON default for missing `int` field).
     *
     * This ensures backward compatibility: existing cached data written before the depth
     * feature was introduced will continue to work correctly.
     */
    @Test
    fun testCachedData_LegacyFormatWithoutDepthKey_DefaultsDepthToZero() {
        // Build legacy JSON manually — no "depth" key in the certificate entry.
        // DateTypeAdapter expects epoch millis as a number; ByteArrayTypeAdapter expects base64.
        val fingerprintBase64 = Base64.getEncoder().encodeToString(fingerprint1)
        val legacyJson = """{"certificates":[{"commonName":"$commonName1","fingerprint":"$fingerprintBase64","expires":$validExpiresMs}],"nextUpdate":$validExpiresMs}"""

        val decoded = CertStore.GSON.fromJson(legacyJson, CachedData::class.java)

        // GSON defaults missing `Int` field to 0 → backward compatible
        assertNotNull(decoded)
        assertEquals(0, decoded.certificates.first().depth)
        assertNull(decoded.domainsConfig)
    }
}
