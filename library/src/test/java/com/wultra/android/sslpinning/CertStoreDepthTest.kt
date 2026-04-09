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
import com.wultra.android.sslpinning.model.GetFingerprintResponse
import com.wultra.android.sslpinning.service.RemoteDataProvider
import com.wultra.android.sslpinning.service.RemoteDataResponse
import com.wultra.android.sslpinning.util.ResponseGenerator
import io.mockk.every
import io.mockk.mockk
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
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
 */
class CertStoreDepthTest : CommonKotlinTest() {

    companion object {
        /** Common name used for most tests. */
        const val CN_1 = "test.example.com"
        /** Second common name. */
        const val CN_2 = "other.example.com"

        /** A known leaf fingerprint (32 bytes of 0x01, base64). */
        val FP_1: ByteArray = ByteArray(32) { 0x01 }
        /** A second known fingerprint (32 bytes of 0x02, base64). */
        val FP_2: ByteArray = ByteArray(32) { 0x02 }
        /** An unknown fingerprint (32 bytes of 0xFF, base64). */
        val FP_UNKNOWN: ByteArray = ByteArray(32) { 0xFF.toByte() }
    }

    private val responseGenerator = ResponseGenerator()

    private fun getCertStore(remoteDataProvider: RemoteDataProvider): CertStore {
        val publicKeyBytes = Base64.getDecoder().decode(
            "BC3kV9OIDnMuVoCdDR9nEA/JidJLTTDLuSA2TSZsGgODSshfbZg31MS90WC/HdbU/A5WL5GmyDkE/iks6INv+XE="
        )
        val config = TestUtils.getCertStoreConfiguration(
            Date(),
            null,
            URL("https://test"),
            publicKeyBytes,
            null
        )
        val store = CertStore(config, cryptoProvider, secureDataStore, remoteDataProvider)
        TestUtils.assignHandler(store, handler)
        return store
    }

    private fun buildRemoteDataProvider(responseData: ByteArray): RemoteDataProvider {
        val remoteDataProvider: RemoteDataProvider = mockk()
        every { remoteDataProvider.getFingerprints(any()) } answers {
            RemoteDataResponse(200, emptyMap(), responseData)
        }
        every { cryptoProvider.ecdsaValidateSignature(any(), any()) } returns true
        return remoteDataProvider
    }

    private fun updateStore(certStore: CertStore): UpdateResult {
        return TestUtils.updateAndCheck(certStore, UpdateMode.FORCED, null)
    }

    // MARK: - Certificate Depth Tests

    /**
     * Tests that a leaf-certificate fingerprint (depth 0) is correctly validated when the
     * server responds with an entry that has no explicit depth (backward compat defaults to 0).
     */
    @Test
    fun testCertDepth_BackwardCompatibility_NoDepthDefaultsToLeaf() {
        val data = responseGenerator.removeAll()
            .append(commonName = CN_1, fingerprint = FP_1)  // no depth → defaults to 0
            .toByteArray()

        val certStore = getCertStore(buildRemoteDataProvider(data))
        assertEquals(UpdateResult.OK, updateStore(certStore))

        // depth 0 should match the stored leaf cert
        assertEquals(ValidationResult.TRUSTED, certStore.validateFingerprint(CN_1, FP_1, 0))
        assertEquals(ValidationResult.TRUSTED, certStore.validateFingerprint(CN_1, FP_1))
    }

    /**
     * Tests that a cert entry pinned at depth 1 (intermediate) is only trusted at depth 1,
     * not at depth 0 or depth 2.
     */
    @Test
    fun testCertDepth_IntermediateCert_MatchesOnlyAtCorrectDepth() {
        val data = responseGenerator.removeAll()
            .append(commonName = CN_1, fingerprint = FP_1, depth = 1)
            .toByteArray()

        val certStore = getCertStore(buildRemoteDataProvider(data))
        assertEquals(UpdateResult.OK, updateStore(certStore))

        // depth 1 — should match
        assertEquals(ValidationResult.TRUSTED, certStore.validateFingerprint(CN_1, FP_1, 1))
        // depth 0 — wrong depth, same CN is known at depth 1 only → empty (no cert at depth 0)
        assertEquals(ValidationResult.EMPTY, certStore.validateFingerprint(CN_1, FP_1, 0))
        // depth 2 — also wrong depth → empty
        assertEquals(ValidationResult.EMPTY, certStore.validateFingerprint(CN_1, FP_1, 2))
    }

    /**
     * Tests that wrong fingerprint at the correct depth returns untrusted.
     */
    @Test
    fun testCertDepth_WrongFingerprintAtCorrectDepth_ReturnsUntrusted() {
        val data = responseGenerator.removeAll()
            .append(commonName = CN_1, fingerprint = FP_1, depth = 1)
            .toByteArray()

        val certStore = getCertStore(buildRemoteDataProvider(data))
        assertEquals(UpdateResult.OK, updateStore(certStore))

        // Known CN at depth 1, but wrong fingerprint → untrusted
        assertEquals(ValidationResult.UNTRUSTED, certStore.validateFingerprint(CN_1, FP_UNKNOWN, 1))
    }

    /**
     * Tests that multiple entries for the same CN at different depths are all correctly stored
     * and validated independently.
     */
    @Test
    fun testCertDepth_MultipleDepthsForSameCN() {
        val data = responseGenerator.removeAll()
            .append(commonName = CN_1, fingerprint = FP_1, depth = 0)
            .append(commonName = CN_1, fingerprint = FP_2, depth = 1)
            .toByteArray()

        val certStore = getCertStore(buildRemoteDataProvider(data))
        assertEquals(UpdateResult.OK, updateStore(certStore))

        // Each depth matches its own fingerprint
        assertEquals(ValidationResult.TRUSTED, certStore.validateFingerprint(CN_1, FP_1, 0))
        assertEquals(ValidationResult.TRUSTED, certStore.validateFingerprint(CN_1, FP_2, 1))

        // Cross-depth: fingerprint 1 at depth 1 → wrong fingerprint at that depth → untrusted
        assertEquals(ValidationResult.UNTRUSTED, certStore.validateFingerprint(CN_1, FP_1, 1))
        // Cross-depth: fingerprint 2 at depth 0 → wrong fingerprint at that depth → untrusted
        assertEquals(ValidationResult.UNTRUSTED, certStore.validateFingerprint(CN_1, FP_2, 0))
    }

    /**
     * Tests that the no-argument [CertStore.validateFingerprint] and
     * [CertStore.validateFingerprint] with depth 0 are equivalent.
     */
    @Test
    fun testCertDepth_DefaultValidateEquivalentToDepthZero() {
        val data = responseGenerator.removeAll()
            .append(commonName = CN_1, fingerprint = FP_1, depth = 0)
            .toByteArray()

        val certStore = getCertStore(buildRemoteDataProvider(data))
        assertEquals(UpdateResult.OK, updateStore(certStore))

        val resultDefault = certStore.validateFingerprint(CN_1, FP_1)
        val resultDepth0 = certStore.validateFingerprint(CN_1, FP_1, 0)
        assertEquals(resultDepth0, resultDefault)
        assertEquals(ValidationResult.TRUSTED, resultDefault)
    }

    /**
     * Tests that a depth-1 entry does not interfere with the legacy depth-less validate path.
     */
    @Test
    fun testCertDepth_DepthOneCertDoesNotAffectLegacyValidate() {
        val data = responseGenerator.removeAll()
            .append(commonName = CN_1, fingerprint = FP_1, depth = 1)
            .toByteArray()

        val certStore = getCertStore(buildRemoteDataProvider(data))
        assertEquals(UpdateResult.OK, updateStore(certStore))

        // Legacy validateFingerprint() (depth 0) — no matching depth-0 cert → empty
        assertEquals(ValidationResult.EMPTY, certStore.validateFingerprint(CN_1, FP_1))
    }

    /**
     * Tests that a certificate depth stored in cache is correctly restored after an app restart
     * (i.e. persisted and loaded from the data store).
     */
    @Test
    fun testCertDepth_PersistedAndRestoredFromCache() {
        // Set up an in-memory store so save/load round-trips work
        val inMemoryStore = mutableMapOf<String, ByteArray>()
        every { secureDataStore.save(any(), any()) } answers {
            val bytes = it.invocation.args[0] as ByteArray
            val key = it.invocation.args[1] as String
            inMemoryStore[key] = bytes
            true
        }
        every { secureDataStore.load(any()) } answers {
            val key = it.invocation.args[0] as String
            inMemoryStore[key]
        }

        val data = responseGenerator.removeAll()
            .append(commonName = CN_1, fingerprint = FP_1, depth = 2)
            .toByteArray()

        val certStore = getCertStore(buildRemoteDataProvider(data))
        assertEquals(UpdateResult.OK, updateStore(certStore))

        // Verify that data was saved
        assertNotNull(inMemoryStore["default"])

        // Simulate app restart: new CertStore backed by the same data store
        val publicKeyBytes = Base64.getDecoder().decode(
            "BC3kV9OIDnMuVoCdDR9nEA/JidJLTTDLuSA2TSZsGgODSshfbZg31MS90WC/HdbU/A5WL5GmyDkE/iks6INv+XE="
        )
        val config = TestUtils.getCertStoreConfiguration(Date(), null, URL("https://test"), publicKeyBytes, null)
        val newCertStore = CertStore(config, cryptoProvider, secureDataStore)
        TestUtils.assignHandler(newCertStore, handler)

        // Should validate correctly from restored cache
        assertEquals(ValidationResult.TRUSTED, newCertStore.validateFingerprint(CN_1, FP_1, 2))
        assertEquals(ValidationResult.EMPTY, newCertStore.validateFingerprint(CN_1, FP_1, 0))
    }

    // MARK: - CertificateInfo model tests

    /**
     * Tests that [CertificateInfo] initialised from a response entry without a depth defaults to 0.
     */
    @Test
    fun testCertificateInfo_DepthDefaultsToZeroWhenAbsent() {
        val entry = GetFingerprintResponse.Entry(
            name = CN_1,
            fingerprint = FP_1,
            expires = Date(System.currentTimeMillis() + TimeUnit.DAYS.toMillis(1)),
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
        val entry = GetFingerprintResponse.Entry(
            name = CN_1,
            fingerprint = FP_1,
            expires = Date(System.currentTimeMillis() + TimeUnit.DAYS.toMillis(1)),
            signature = null,
            depth = 2
        )
        val info = CertificateInfo(entry)
        assertEquals(2, info.depth)
    }

    /**
     * Tests that the primary [CertificateInfo] constructor defaults depth to 0.
     */
    @Test
    fun testCertificateInfo_DefaultDepthIsZero() {
        val info = CertificateInfo(
            commonName = CN_1,
            fingerprint = FP_1,
            expires = Date(System.currentTimeMillis() + TimeUnit.DAYS.toMillis(1))
        )
        assertEquals(0, info.depth)
    }

    /**
     * Tests [CertificateInfo] equality: two entries with identical fields but different depths are not equal.
     */
    @Test
    fun testCertificateInfo_EqualityConsidersDepth() {
        val expires = Date(System.currentTimeMillis() + TimeUnit.DAYS.toMillis(1))
        val infoDepth0 = CertificateInfo(commonName = CN_1, fingerprint = FP_1, expires = expires, depth = 0)
        val infoDepth1 = CertificateInfo(commonName = CN_1, fingerprint = FP_1, expires = expires, depth = 1)
        val infoDepth0Copy = CertificateInfo(commonName = CN_1, fingerprint = FP_1, expires = expires, depth = 0)

        assertNotEquals(infoDepth0, infoDepth1)
        assertEquals(infoDepth0, infoDepth0Copy)
    }

    // MARK: - CachedData serialization

    /**
     * Tests that [CachedData] with depth values round-trips correctly through JSON.
     */
    @Test
    fun testCachedData_DepthValuesRoundTrip() {
        val expires = Date(System.currentTimeMillis() + TimeUnit.DAYS.toMillis(1))
        val certs = arrayOf(
            CertificateInfo(commonName = CN_1, fingerprint = FP_1, expires = expires, depth = 0),
            CertificateInfo(commonName = CN_1, fingerprint = FP_2, expires = expires, depth = 1),
            CertificateInfo(commonName = CN_2, fingerprint = FP_2, expires = expires, depth = 2)
        )
        val cached = CachedData(certificates = certs, nextUpdate = expires, domainsConfig = null)

        val json = CertStore.GSON.toJson(cached)
        val decoded = CertStore.GSON.fromJson(json, CachedData::class.java)

        assertNotNull(decoded)
        assertEquals(certs.size, decoded.certificates.size)
        assertEquals(0, decoded.certificates[0].depth)
        assertEquals(1, decoded.certificates[1].depth)
        assertEquals(2, decoded.certificates[2].depth)
    }

    /**
     * Tests that legacy [CachedData] JSON without a "depth" key in certificates can still be
     * decoded by GSON, and that the depth field is null (matching the absent-key behavior,
     * analogous to iOS where missing "d" key results in nil depth).
     */
    @Test
    fun testCachedData_LegacyFormatWithoutDepthKey() {
        val fingerprintBase64 = Base64.getEncoder().encodeToString(FP_1)
        val expiresMs = System.currentTimeMillis() + TimeUnit.DAYS.toMillis(1)
        val legacyJson = """
        {
            "certificates": [
                {
                    "commonName": "$CN_1",
                    "fingerprint": "$fingerprintBase64",
                    "expires": $expiresMs
                }
            ],
            "nextUpdate": $expiresMs
        }
        """.trimIndent()

        // GSON sets nullable Int? fields to null when the key is absent in JSON
        val decoded = CertStore.GSON.fromJson(legacyJson, CachedData::class.java)
        assertNotNull("Legacy cache without 'depth' key should still decode with GSON", decoded)
        assertNull("Missing 'depth' key should result in null depth", decoded.certificates[0].depth)
    }
}
