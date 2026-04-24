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

import com.wultra.android.sslpinning.model.DomainConfig
import com.wultra.android.sslpinning.model.DomainsConfig
import com.wultra.android.sslpinning.service.RemoteDataProvider
import com.wultra.android.sslpinning.service.RemoteDataResponse
import com.wultra.android.sslpinning.util.ResponseGenerator
import io.mockk.clearMocks
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.URL
import java.util.Base64
import java.util.Date

/**
 * Tests for [DomainsConfig] functionality: domain-specific SSL pinning bypass,
 * integration with [CertStore] validation, and [DomainsConfig] serialization in
 * [com.wultra.android.sslpinning.model.CachedData].
 */
class CertStoreDomainsConfigTest : CommonKotlinTest() {

    companion object {
        const val CN_1 = "test.example.com"
        const val CN_2 = "other.example.com"
        const val CN_UNKNOWN = "unknown.example.com"

        val FP_1: ByteArray = ByteArray(32) { 0x01 }
        val FP_UNKNOWN: ByteArray = ByteArray(32) { 0xFF.toByte() }
    }

    private val responseGenerator = ResponseGenerator()

    private fun getCertStore(remoteDataProvider: RemoteDataProvider): CertStore {
        val publicKeyBytes = Base64.getDecoder().decode(
            "BC3kV9OIDnMuVoCdDR9nEA/JidJLTTDLuSA2TSZsGgODSshfbZg31MS90WC/HdbU/A5WL5GmyDkE/iks6INv+XE="
        )
        val config = TestUtils.getCertStoreConfiguration(
            Date(), null, URL("https://test"), publicKeyBytes, null
        )
        val store = CertStore(config, cryptoProvider, secureDataStore, remoteDataProvider)
        TestUtils.assignHandler(store, handler)
        return store
    }

    private fun buildRemoteDataProvider(responseData: ByteArray): RemoteDataProvider {
        val remoteDataProvider: RemoteDataProvider = mockk()
        every { remoteDataProvider.getFingerprints(any()) } answers {
            RemoteDataResponse(200, sigHeader, responseData)
        }
        every { cryptoProvider.ecdsaValidateSignature(any(), any()) } returns true
        return remoteDataProvider
    }

    private fun updateStore(certStore: CertStore): UpdateResult {
        return TestUtils.updateAndCheck(certStore, UpdateMode.FORCED, null)
    }

    // MARK: - DomainsConfig model tests

    /** Tests that a listed domain with sslPinningRequired=false returns false. */
    @Test
    fun testDomainsConfig_ListedDomainPinningNotRequired() {
        val config = DomainsConfig(
            sslPinningRequiredForUnlisted = true,
            domains = listOf(DomainConfig(commonName = CN_1, sslPinningRequired = false))
        )
        assertFalse(config.isPinningRequired(CN_1))
    }

    /** Tests that a listed domain with sslPinningRequired=true returns true. */
    @Test
    fun testDomainsConfig_ListedDomainPinningRequired() {
        val config = DomainsConfig(
            sslPinningRequiredForUnlisted = false,
            domains = listOf(DomainConfig(commonName = CN_1, sslPinningRequired = true))
        )
        assertTrue(config.isPinningRequired(CN_1))
    }

    /** Tests that an unlisted domain falls back to sslPinningRequiredForUnlisted=true. */
    @Test
    fun testDomainsConfig_UnlistedDomainFallsBackToRequiredTrue() {
        val config = DomainsConfig(
            sslPinningRequiredForUnlisted = true,
            domains = listOf(DomainConfig(commonName = CN_1, sslPinningRequired = false))
        )
        assertTrue(config.isPinningRequired(CN_UNKNOWN))
    }

    /** Tests that an unlisted domain falls back to sslPinningRequiredForUnlisted=false. */
    @Test
    fun testDomainsConfig_UnlistedDomainFallsBackToRequiredFalse() {
        val config = DomainsConfig(
            sslPinningRequiredForUnlisted = false,
            domains = listOf(DomainConfig(commonName = CN_1, sslPinningRequired = true))
        )
        assertFalse(config.isPinningRequired(CN_UNKNOWN))
    }

    /** Tests that DomainsConfig with an empty domains array uses sslPinningRequiredForUnlisted for every domain. */
    @Test
    fun testDomainsConfig_EmptyDomainsListUsesDefaultForAll() {
        val configRequired = DomainsConfig(sslPinningRequiredForUnlisted = true, domains = emptyList())
        val configNotRequired = DomainsConfig(sslPinningRequiredForUnlisted = false, domains = emptyList())

        assertTrue(configRequired.isPinningRequired(CN_1))
        assertTrue(configRequired.isPinningRequired(CN_UNKNOWN))
        assertFalse(configNotRequired.isPinningRequired(CN_1))
        assertFalse(configNotRequired.isPinningRequired(CN_UNKNOWN))
    }

    // MARK: - DomainsConfig integration with CertStore

    /**
     * Tests that when DomainsConfig marks a domain as pinning-not-required, validation returns TRUSTED
     * regardless of the fingerprint.
     */
    @Test
    fun testDomainsConfig_PinningNotRequired_ReturnsTrustedWithAnyFingerprint() {
        val domainsConfigJson = """{"sslPinningRequiredForUnlisted":true,"domains":[{"name":"$CN_1","sslPinningRequired":false}]}"""
        val data = responseGenerator.removeAll()
            .append(commonName = CN_1, fingerprint = FP_1)
            .setDomainsConfigJson(domainsConfigJson)
            .toByteArray()

        val certStore = getCertStore(buildRemoteDataProvider(data))
        assertEquals(UpdateResult.OK, updateStore(certStore))

        // Pinning not required for CN_1 → always trusted regardless of fingerprint
        assertEquals(ValidationResult.TRUSTED, certStore.validateFingerprint(CN_1, FP_UNKNOWN))
        assertEquals(ValidationResult.TRUSTED, certStore.validateFingerprint(CN_1, FP_1))
    }

    /**
     * Tests that when DomainsConfig marks a domain as pinning-not-required, the depth overload also
     * returns TRUSTED immediately.
     */
    @Test
    fun testDomainsConfig_PinningNotRequired_ReturnsTrustedWithDepth() {
        val domainsConfigJson = """{"sslPinningRequiredForUnlisted":true,"domains":[{"name":"$CN_1","sslPinningRequired":false}]}"""
        val data = responseGenerator.removeAll()
            .append(commonName = CN_1, fingerprint = FP_1, depth = 1)
            .setDomainsConfigJson(domainsConfigJson)
            .toByteArray()

        val certStore = getCertStore(buildRemoteDataProvider(data))
        assertEquals(UpdateResult.OK, updateStore(certStore))

        // Pinning not required → trusted at any depth, any fingerprint
        assertEquals(ValidationResult.TRUSTED, certStore.validateFingerprint(CN_1, FP_UNKNOWN, 0))
        assertEquals(ValidationResult.TRUSTED, certStore.validateFingerprint(CN_1, FP_UNKNOWN, 1))
        assertEquals(ValidationResult.TRUSTED, certStore.validateFingerprint(CN_1, FP_UNKNOWN, 2))
    }

    /**
     * Tests that when DomainsConfig marks a domain as pinning-required, normal fingerprint
     * validation takes place (trusted/untrusted/empty as usual).
     */
    @Test
    fun testDomainsConfig_PinningRequired_NormalValidationApplied() {
        val domainsConfigJson = """{"sslPinningRequiredForUnlisted":false,"domains":[{"name":"$CN_1","sslPinningRequired":true}]}"""
        val data = responseGenerator.removeAll()
            .append(commonName = CN_1, fingerprint = FP_1)
            .setDomainsConfigJson(domainsConfigJson)
            .toByteArray()

        val certStore = getCertStore(buildRemoteDataProvider(data))
        assertEquals(UpdateResult.OK, updateStore(certStore))

        // Pinning required for CN_1 → regular matching rules
        assertEquals(ValidationResult.TRUSTED, certStore.validateFingerprint(CN_1, FP_1))
        assertEquals(ValidationResult.UNTRUSTED, certStore.validateFingerprint(CN_1, FP_UNKNOWN))
    }

    /**
     * Tests that when DomainsConfig is present and marks an unlisted domain as pinning-not-required
     * (via sslPinningRequiredForUnlisted=false), any fingerprint is trusted for that domain.
     */
    @Test
    fun testDomainsConfig_UnlistedDomainPinningNotRequired_TrustedForAnyFingerprint() {
        val domainsConfigJson = """{"sslPinningRequiredForUnlisted":false,"domains":[{"name":"$CN_1","sslPinningRequired":true}]}"""
        val data = responseGenerator.removeAll()
            .append(commonName = CN_1, fingerprint = FP_1)
            .setDomainsConfigJson(domainsConfigJson)
            .toByteArray()

        val certStore = getCertStore(buildRemoteDataProvider(data))
        assertEquals(UpdateResult.OK, updateStore(certStore))

        // CN_2 is not in domains list and unlisted pinning is false → trusted
        assertEquals(ValidationResult.TRUSTED, certStore.validateFingerprint(CN_2, FP_UNKNOWN))
    }

    /**
     * Tests that when no DomainsConfig is present in the response, normal validation behavior applies.
     */
    @Test
    fun testDomainsConfig_Absent_NormalValidationApplied() {
        val data = responseGenerator.removeAll()
            .append(commonName = CN_1, fingerprint = FP_1)
            // no domainsConfig set
            .toByteArray()

        val certStore = getCertStore(buildRemoteDataProvider(data))
        assertEquals(UpdateResult.OK, updateStore(certStore))

        assertEquals(ValidationResult.TRUSTED, certStore.validateFingerprint(CN_1, FP_1))
        assertEquals(ValidationResult.UNTRUSTED, certStore.validateFingerprint(CN_1, FP_UNKNOWN))
        assertEquals(ValidationResult.EMPTY, certStore.validateFingerprint(CN_2, FP_UNKNOWN))
    }

    /**
     * Tests that DomainsConfig is persisted in CachedData and survives an app restart.
     */
    @Test
    fun testDomainsConfig_PersistedAndRestoredFromCache() {
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

        val domainsConfigJson = """{"sslPinningRequiredForUnlisted":true,"domains":[{"name":"$CN_1","sslPinningRequired":false}]}"""
        val data = responseGenerator.removeAll()
            .append(commonName = CN_1, fingerprint = FP_1)
            .setDomainsConfigJson(domainsConfigJson)
            .toByteArray()

        val certStore = getCertStore(buildRemoteDataProvider(data))
        assertEquals(UpdateResult.OK, updateStore(certStore))

        // Simulate app restart: new CertStore backed by the same data store
        val publicKeyBytes = Base64.getDecoder().decode(
            "BC3kV9OIDnMuVoCdDR9nEA/JidJLTTDLuSA2TSZsGgODSshfbZg31MS90WC/HdbU/A5WL5GmyDkE/iks6INv+XE="
        )
        val config = TestUtils.getCertStoreConfiguration(Date(), null, URL("https://test"), publicKeyBytes, null)
        val newCertStore = CertStore(config, cryptoProvider, secureDataStore)
        TestUtils.assignHandler(newCertStore, handler)

        // DomainsConfig should have been restored from cache → pinning not required
        assertEquals(ValidationResult.TRUSTED, newCertStore.validateFingerprint(CN_1, FP_UNKNOWN))
    }

    /**
     * Tests that a subsequent update with no DomainsConfig clears it from cache.
     */
    @Test
    fun testDomainsConfig_ClearedOnUpdateWithoutIt() {
        val publicKeyBytes = Base64.getDecoder().decode(
            "BC3kV9OIDnMuVoCdDR9nEA/JidJLTTDLuSA2TSZsGgODSshfbZg31MS90WC/HdbU/A5WL5GmyDkE/iks6INv+XE="
        )
        val config = TestUtils.getCertStoreConfiguration(Date(), null, URL("https://test"), publicKeyBytes, null)
        val remoteDataProvider: RemoteDataProvider = mockk()
        val certStore = CertStore(config, cryptoProvider, secureDataStore, remoteDataProvider)
        TestUtils.assignHandler(certStore, handler)
        every { cryptoProvider.ecdsaValidateSignature(any(), any()) } returns true

        val domainsConfigJson = """{"sslPinningRequiredForUnlisted":true,"domains":[{"name":"$CN_1","sslPinningRequired":false}]}"""

        // First update: include DomainsConfig
        every { remoteDataProvider.getFingerprints(any()) } answers {
            RemoteDataResponse(
                200,
                sigHeader,
                responseGenerator.removeAll()
                    .append(commonName = CN_1, fingerprint = FP_1)
                    .setDomainsConfigJson(domainsConfigJson)
                    .toByteArray()
            )
        }
        assertEquals(UpdateResult.OK, TestUtils.updateAndCheck(certStore, UpdateMode.FORCED, null))
        // With bypass active, validation should return trusted
        assertEquals(ValidationResult.TRUSTED, certStore.validateFingerprint(CN_1, FP_UNKNOWN))

        // Second update: no DomainsConfig
        every { remoteDataProvider.getFingerprints(any()) } answers {
            RemoteDataResponse(
                200,
                sigHeader,
                responseGenerator.removeAll()
                    .append(commonName = CN_1, fingerprint = FP_1)
                    .toByteArray()
            )
        }
        assertEquals(UpdateResult.OK, TestUtils.updateAndCheck(certStore, UpdateMode.FORCED, null))
        // Without bypass, normal validation is restored
        assertEquals(ValidationResult.UNTRUSTED, certStore.validateFingerprint(CN_1, FP_UNKNOWN))
        assertEquals(ValidationResult.TRUSTED, certStore.validateFingerprint(CN_1, FP_1))
    }

    // MARK: - isDomainsConfigPinningRequired (via validateCertificateData)

    /**
     * When domainsConfig is absent, SHA-256 must be computed because pinning is required.
     */
    @Test
    fun testIsDomainsConfigPinningRequired_AbsentConfig_PinningRequired() {
        val data = responseGenerator.removeAll()
            .append(commonName = CN_1, fingerprint = FP_1)
            // no domainsConfig
            .toByteArray()

        val certStore = getCertStore(buildRemoteDataProvider(data))
        assertEquals(UpdateResult.OK, updateStore(certStore))

        clearMocks(cryptoProvider, answers = false)

        val certData = ByteArray(64) { 0xAA.toByte() }
        certStore.validateCertificateData(CN_1, certData)

        // SHA-256 must be computed because no domainsConfig is present → pinning required
        verify(exactly = 1) { cryptoProvider.hashSha256(certData) }
    }

    /**
     * When domainsConfig requires pinning, [CertStore.validateCertificateData] must proceed
     * normally: SHA-256 is computed and fingerprint matching is performed.
     */
    @Test
    fun testIsDomainsConfigPinningRequired_PinningRequired_ComputesSha256() {
        val domainsConfigJson = """{"sslPinningRequiredForUnlisted":false,"domains":[{"name":"$CN_1","sslPinningRequired":true}]}"""
        val data = responseGenerator.removeAll()
            .append(commonName = CN_1, fingerprint = FP_1)
            .setDomainsConfigJson(domainsConfigJson)
            .toByteArray()

        val certStore = getCertStore(buildRemoteDataProvider(data))
        assertEquals(UpdateResult.OK, updateStore(certStore))

        clearMocks(cryptoProvider, answers = false)

        val certData = ByteArray(64) { 0xAA.toByte() }
        certStore.validateCertificateData(CN_1, certData)

        // SHA-256 must be computed because pinning is required for this domain
        verify(exactly = 1) { cryptoProvider.hashSha256(certData) }
    }

    // MARK: - domainsConfig takes priority over expectedCommonNames

    /**
     * When domainsConfig bypasses pinning for a domain, the result must be [ValidationResult.TRUSTED]
     * even if the domain is NOT listed in [CertStoreConfiguration.expectedCommonNames].
     * This verifies that the domainsConfig check runs before the expectedCommonNames guard.
     */
    @Test
    fun testDomainsConfig_TakesPriorityOverExpectedCommonNames_Bypass() {
        val publicKeyBytes = Base64.getDecoder().decode(
            "BC3kV9OIDnMuVoCdDR9nEA/JidJLTTDLuSA2TSZsGgODSshfbZg31MS90WC/HdbU/A5WL5GmyDkE/iks6INv+XE="
        )
        // expectedCommonNames does NOT include CN_1
        val config = TestUtils.getCertStoreConfiguration(Date(), arrayOf(CN_2), URL("https://test"), publicKeyBytes, null)
        val certStore = CertStore(config, cryptoProvider, secureDataStore, buildRemoteDataProvider(ByteArray(0)))
        TestUtils.assignHandler(certStore, handler)

        val domainsConfigJson = """{"sslPinningRequiredForUnlisted":true,"domains":[{"name":"$CN_1","sslPinningRequired":false}]}"""
        val data = responseGenerator.removeAll()
            .append(commonName = CN_2, fingerprint = FP_1)
            .setDomainsConfigJson(domainsConfigJson)
            .toByteArray()

        val remoteDataProvider = buildRemoteDataProvider(data)
        val certStoreWithExpected = CertStore(config, cryptoProvider, secureDataStore, remoteDataProvider)
        TestUtils.assignHandler(certStoreWithExpected, handler)
        assertEquals(UpdateResult.OK, TestUtils.updateAndCheck(certStoreWithExpected, UpdateMode.FORCED, null))

        // CN_1 is NOT in expectedCommonNames, but domainsConfig disables pinning for it.
        // domainsConfig is checked first → must return TRUSTED, not UNTRUSTED.
        assertEquals(ValidationResult.TRUSTED, certStoreWithExpected.validateFingerprint(CN_1, FP_UNKNOWN))

        // CN_2 is in expectedCommonNames and pinning is required → normal rules apply
        assertEquals(ValidationResult.TRUSTED, certStoreWithExpected.validateFingerprint(CN_2, FP_1))
        assertEquals(ValidationResult.UNTRUSTED, certStoreWithExpected.validateFingerprint(CN_2, FP_UNKNOWN))
    }

    /**
     * When domainsConfig requires pinning for a domain NOT in [CertStoreConfiguration.expectedCommonNames],
     * the expectedCommonNames guard must still reject it with [ValidationResult.UNTRUSTED].
     */
    @Test
    fun testDomainsConfig_PinningRequired_ExpectedCommonNamesStillEnforced() {
        val publicKeyBytes = Base64.getDecoder().decode(
            "BC3kV9OIDnMuVoCdDR9nEA/JidJLTTDLuSA2TSZsGgODSshfbZg31MS90WC/HdbU/A5WL5GmyDkE/iks6INv+XE="
        )
        // expectedCommonNames does NOT include CN_1
        val config = TestUtils.getCertStoreConfiguration(Date(), arrayOf(CN_2), URL("https://test"), publicKeyBytes, null)

        val domainsConfigJson = """{"sslPinningRequiredForUnlisted":true,"domains":[{"name":"$CN_1","sslPinningRequired":true}]}"""
        val data = responseGenerator.removeAll()
            .append(commonName = CN_2, fingerprint = FP_1)
            .setDomainsConfigJson(domainsConfigJson)
            .toByteArray()

        val remoteDataProvider = buildRemoteDataProvider(data)
        val certStore = CertStore(config, cryptoProvider, secureDataStore, remoteDataProvider)
        TestUtils.assignHandler(certStore, handler)
        assertEquals(UpdateResult.OK, TestUtils.updateAndCheck(certStore, UpdateMode.FORCED, null))

        // CN_1 is not in expectedCommonNames and pinning IS required → UNTRUSTED
        assertEquals(ValidationResult.UNTRUSTED, certStore.validateFingerprint(CN_1, FP_1))
    }
}
