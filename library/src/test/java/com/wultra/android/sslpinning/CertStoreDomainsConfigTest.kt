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
import com.wultra.android.sslpinning.model.DomainConfig
import com.wultra.android.sslpinning.model.DomainsConfig
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
 * Tests for [DomainsConfig] functionality: domain-specific SSL pinning bypass,
 * integration with [CertStore] validation, and [DomainsConfig] serialization in [CachedData].
 *
 * Mirrors the iOS `CertStoreTests_DomainsConfig` test class.
 */
class CertStoreDomainsConfigTest : CommonKotlinTest() {

    // Common test fixtures
    private val commonName1 = "test.example.com"
    private val commonName2 = "other.example.com"
    private val commonNameUnknown = "unknown.example.com"
    private val fingerprint1 = ByteArray(32) { 1 }
    private val fingerprint2 = ByteArray(32) { 2 }
    private val fingerprintUnknown = ByteArray(32) { 99 }
    private val validExpiresMs: Long = System.currentTimeMillis() + TimeUnit.DAYS.toMillis(365)

    private val responseGenerator = ResponseGenerator()

    private fun buildCertStore(remoteDataProvider: RemoteDataProvider): CertStore {
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

    private fun buildRemoteProvider(responseData: ByteArray): RemoteDataProvider {
        val provider: RemoteDataProvider = mockk()
        every { provider.getFingerprints(any()) } answers {
            RemoteDataResponse(200, emptyMap(), responseData)
        }
        return provider
    }

    // -------------------------------------------------------------------------
    // DomainsConfig model tests
    // -------------------------------------------------------------------------

    /** Tests that a listed domain with sslPinningRequired=false returns false. */
    @Test
    fun testDomainsConfig_ListedDomainPinningNotRequired() {
        val config = DomainsConfig(
            sslPinningRequiredForUnlisted = true,
            domains = listOf(DomainConfig(name = commonName1, sslPinningRequired = false))
        )
        assertEquals(false, config.isPinningRequired(commonName1))
    }

    /** Tests that a listed domain with sslPinningRequired=true returns true. */
    @Test
    fun testDomainsConfig_ListedDomainPinningRequired() {
        val config = DomainsConfig(
            sslPinningRequiredForUnlisted = false,
            domains = listOf(DomainConfig(name = commonName1, sslPinningRequired = true))
        )
        assertEquals(true, config.isPinningRequired(commonName1))
    }

    /** Tests that an unlisted domain falls back to sslPinningRequiredForUnlisted=true. */
    @Test
    fun testDomainsConfig_UnlistedDomainFallsBackToRequiredTrue() {
        val config = DomainsConfig(
            sslPinningRequiredForUnlisted = true,
            domains = listOf(DomainConfig(name = commonName1, sslPinningRequired = false))
        )
        assertEquals(true, config.isPinningRequired(commonNameUnknown))
    }

    /** Tests that an unlisted domain falls back to sslPinningRequiredForUnlisted=false. */
    @Test
    fun testDomainsConfig_UnlistedDomainFallsBackToRequiredFalse() {
        val config = DomainsConfig(
            sslPinningRequiredForUnlisted = false,
            domains = listOf(DomainConfig(name = commonName1, sslPinningRequired = true))
        )
        assertEquals(false, config.isPinningRequired(commonNameUnknown))
    }

    /** Tests that an empty domains list uses sslPinningRequiredForUnlisted for every domain. */
    @Test
    fun testDomainsConfig_EmptyDomainsListUsesDefaultForAll() {
        val configRequired = DomainsConfig(sslPinningRequiredForUnlisted = true, domains = emptyList())
        val configNotRequired = DomainsConfig(sslPinningRequiredForUnlisted = false, domains = emptyList())

        assertEquals(true, configRequired.isPinningRequired(commonName1))
        assertEquals(true, configRequired.isPinningRequired(commonNameUnknown))
        assertEquals(false, configNotRequired.isPinningRequired(commonName1))
        assertEquals(false, configNotRequired.isPinningRequired(commonNameUnknown))
    }

    // -------------------------------------------------------------------------
    // DomainsConfig integration with CertStore
    // -------------------------------------------------------------------------

    /**
     * Tests that when [DomainsConfig] marks a domain as pinning-not-required, validation
     * returns [ValidationResult.TRUSTED] regardless of the fingerprint.
     */
    @Test
    fun testDomainsConfig_PinningNotRequired_ReturnsTrustedWithAnyFingerprint() {
        every { cryptoProvider.ecdsaValidateSignature(any(), any()) } returns true

        val domains = DomainsConfig(
            sslPinningRequiredForUnlisted = true,
            domains = listOf(DomainConfig(name = commonName1, sslPinningRequired = false))
        )

        val responseData = responseGenerator
            .removeAll()
            .append(commonName = commonName1, fingerprint = fingerprint1)
            .setDomainsConfig(domains)
            .data()

        val store = buildCertStore(buildRemoteProvider(responseData))
        TestUtils.updateAndCheck(store, UpdateMode.FORCED, UpdateResult.OK)

        // Pinning not required for commonName1 → always trusted regardless of fingerprint
        assertEquals(ValidationResult.TRUSTED, store.validateFingerprint(commonName1, fingerprintUnknown))
        assertEquals(ValidationResult.TRUSTED, store.validateFingerprint(commonName1, fingerprint1))
    }

    /**
     * Tests that when [DomainsConfig] marks a domain as pinning-not-required, the depth overload
     * also returns [ValidationResult.TRUSTED] immediately.
     */
    @Test
    fun testDomainsConfig_PinningNotRequired_ReturnsTrustedWithDepth() {
        every { cryptoProvider.ecdsaValidateSignature(any(), any()) } returns true

        val domains = DomainsConfig(
            sslPinningRequiredForUnlisted = true,
            domains = listOf(DomainConfig(name = commonName1, sslPinningRequired = false))
        )

        val responseData = responseGenerator
            .removeAll()
            .append(commonName = commonName1, fingerprint = fingerprint1, depth = 1)
            .setDomainsConfig(domains)
            .data()

        val store = buildCertStore(buildRemoteProvider(responseData))
        TestUtils.updateAndCheck(store, UpdateMode.FORCED, UpdateResult.OK)

        // Pinning not required → trusted at any depth, any fingerprint
        assertEquals(ValidationResult.TRUSTED, store.validateFingerprint(commonName1, fingerprintUnknown, 0))
        assertEquals(ValidationResult.TRUSTED, store.validateFingerprint(commonName1, fingerprintUnknown, 1))
        assertEquals(ValidationResult.TRUSTED, store.validateFingerprint(commonName1, fingerprintUnknown, 2))
    }

    /**
     * Tests that when [DomainsConfig] marks a domain as pinning-required, normal fingerprint
     * validation takes place (trusted/untrusted/empty as usual).
     */
    @Test
    fun testDomainsConfig_PinningRequired_NormalValidationApplied() {
        every { cryptoProvider.ecdsaValidateSignature(any(), any()) } returns true

        val domains = DomainsConfig(
            sslPinningRequiredForUnlisted = false,
            domains = listOf(DomainConfig(name = commonName1, sslPinningRequired = true))
        )

        val responseData = responseGenerator
            .removeAll()
            .append(commonName = commonName1, fingerprint = fingerprint1)
            .setDomainsConfig(domains)
            .data()

        val store = buildCertStore(buildRemoteProvider(responseData))
        TestUtils.updateAndCheck(store, UpdateMode.FORCED, UpdateResult.OK)

        // Pinning required for commonName1 → regular matching rules
        assertEquals(ValidationResult.TRUSTED, store.validateFingerprint(commonName1, fingerprint1))
        assertEquals(ValidationResult.UNTRUSTED, store.validateFingerprint(commonName1, fingerprintUnknown))
    }

    /**
     * Tests that when [DomainsConfig] marks an unlisted domain as pinning-not-required
     * (via sslPinningRequiredForUnlisted=false), any fingerprint is trusted for that domain.
     */
    @Test
    fun testDomainsConfig_UnlistedDomainPinningNotRequired_TrustedForAnyFingerprint() {
        every { cryptoProvider.ecdsaValidateSignature(any(), any()) } returns true

        val domains = DomainsConfig(
            sslPinningRequiredForUnlisted = false,
            domains = listOf(DomainConfig(name = commonName1, sslPinningRequired = true))
        )

        val responseData = responseGenerator
            .removeAll()
            .append(commonName = commonName1, fingerprint = fingerprint1)
            .setDomainsConfig(domains)
            .data()

        val store = buildCertStore(buildRemoteProvider(responseData))
        TestUtils.updateAndCheck(store, UpdateMode.FORCED, UpdateResult.OK)

        // commonName2 is not in domains list and unlisted pinning is false → trusted
        assertEquals(ValidationResult.TRUSTED, store.validateFingerprint(commonName2, fingerprintUnknown))
    }

    /**
     * Tests that when no [DomainsConfig] is present in the response, normal validation applies.
     */
    @Test
    fun testDomainsConfig_Absent_NormalValidationApplied() {
        every { cryptoProvider.ecdsaValidateSignature(any(), any()) } returns true

        val responseData = responseGenerator
            .removeAll()
            .append(commonName = commonName1, fingerprint = fingerprint1)
            // no domainsConfig set
            .data()

        val store = buildCertStore(buildRemoteProvider(responseData))
        TestUtils.updateAndCheck(store, UpdateMode.FORCED, UpdateResult.OK)

        assertEquals(ValidationResult.TRUSTED, store.validateFingerprint(commonName1, fingerprint1))
        assertEquals(ValidationResult.UNTRUSTED, store.validateFingerprint(commonName1, fingerprintUnknown))
        assertEquals(ValidationResult.EMPTY, store.validateFingerprint(commonName2, fingerprintUnknown))
    }

    /**
     * Tests that a subsequent update with no [DomainsConfig] clears it from cache,
     * restoring normal validation behaviour.
     */
    @Test
    fun testDomainsConfig_ClearedOnUpdateWithoutIt() {
        every { cryptoProvider.ecdsaValidateSignature(any(), any()) } returns true

        val domains = DomainsConfig(
            sslPinningRequiredForUnlisted = true,
            domains = listOf(DomainConfig(name = commonName1, sslPinningRequired = false))
        )

        val provider: RemoteDataProvider = mockk()

        // First update: include DomainsConfig
        every { provider.getFingerprints(any()) } answers {
            RemoteDataResponse(
                200, emptyMap(),
                responseGenerator
                    .removeAll()
                    .append(commonName = commonName1, fingerprint = fingerprint1)
                    .setDomainsConfig(domains)
                    .data()
            )
        }

        val store = buildCertStore(provider)
        TestUtils.updateAndCheck(store, UpdateMode.FORCED, UpdateResult.OK)
        // Pinning disabled → trusted
        assertEquals(ValidationResult.TRUSTED, store.validateFingerprint(commonName1, fingerprintUnknown))

        // Second update: DomainsConfig absent
        every { provider.getFingerprints(any()) } answers {
            RemoteDataResponse(
                200, emptyMap(),
                responseGenerator
                    .removeAll()
                    .append(commonName = commonName1, fingerprint = fingerprint1)
                    // no domainsConfig
                    .data()
            )
        }

        TestUtils.updateAndCheck(store, UpdateMode.FORCED, UpdateResult.OK)

        // Now normal validation applies again
        assertEquals(ValidationResult.TRUSTED, store.validateFingerprint(commonName1, fingerprint1))
        assertEquals(ValidationResult.UNTRUSTED, store.validateFingerprint(commonName1, fingerprintUnknown))
    }

    // -------------------------------------------------------------------------
    // Combined: Depth + DomainsConfig
    // -------------------------------------------------------------------------

    /**
     * Tests that [DomainsConfig] bypass takes precedence over depth matching — when pinning
     * is not required for a domain, it returns [ValidationResult.TRUSTED] without checking
     * fingerprint or depth.
     */
    @Test
    fun testDepthAndDomainsConfig_BypassTakesPrecedenceOverDepthCheck() {
        every { cryptoProvider.ecdsaValidateSignature(any(), any()) } returns true

        val domains = DomainsConfig(
            sslPinningRequiredForUnlisted = true,
            domains = listOf(DomainConfig(name = commonName1, sslPinningRequired = false))
        )

        // Store a cert only at depth 2
        val responseData = responseGenerator
            .removeAll()
            .append(commonName = commonName1, fingerprint = fingerprint1, depth = 2)
            .setDomainsConfig(domains)
            .data()

        val store = buildCertStore(buildRemoteProvider(responseData))
        TestUtils.updateAndCheck(store, UpdateMode.FORCED, UpdateResult.OK)

        // Pinning not required → trusted even at wrong depth with wrong fingerprint
        assertEquals(ValidationResult.TRUSTED, store.validateFingerprint(commonName1, fingerprintUnknown, 0))
        assertEquals(ValidationResult.TRUSTED, store.validateFingerprint(commonName1, fingerprintUnknown, 1))
        assertEquals(ValidationResult.TRUSTED, store.validateFingerprint(commonName1, fingerprintUnknown, 2))
    }

    /**
     * Tests that [DomainsConfig] pinning-required for one domain does not affect another domain
     * whose pinning is bypassed, and vice versa.
     */
    @Test
    fun testDepthAndDomainsConfig_MultipleDomainsMixedPinningRequirements() {
        every { cryptoProvider.ecdsaValidateSignature(any(), any()) } returns true

        val domains = DomainsConfig(
            sslPinningRequiredForUnlisted = true,
            domains = listOf(
                DomainConfig(name = commonName1, sslPinningRequired = false),
                DomainConfig(name = commonName2, sslPinningRequired = true)
            )
        )

        val responseData = responseGenerator
            .removeAll()
            .append(commonName = commonName1, fingerprint = fingerprint1, depth = 0)
            .append(commonName = commonName2, fingerprint = fingerprint2, depth = 1)
            .setDomainsConfig(domains)
            .data()

        val store = buildCertStore(buildRemoteProvider(responseData))
        TestUtils.updateAndCheck(store, UpdateMode.FORCED, UpdateResult.OK)

        // commonName1: pinning not required → always trusted
        assertEquals(ValidationResult.TRUSTED, store.validateFingerprint(commonName1, fingerprintUnknown, 0))
        assertEquals(ValidationResult.TRUSTED, store.validateFingerprint(commonName1, fingerprintUnknown, 1))

        // commonName2: pinning required, cert stored at depth 1
        assertEquals(ValidationResult.TRUSTED, store.validateFingerprint(commonName2, fingerprint2, 1))
        assertEquals(ValidationResult.UNTRUSTED, store.validateFingerprint(commonName2, fingerprintUnknown, 1))
        assertEquals(ValidationResult.EMPTY, store.validateFingerprint(commonName2, fingerprint2, 0))
    }

    // -------------------------------------------------------------------------
    // CachedData serialization
    // -------------------------------------------------------------------------

    /**
     * Tests that [CachedData] round-trips correctly through GSON with both
     * [DomainsConfig] and certificate depths.
     */
    @Test
    fun testCachedData_SerializationWithDomainsConfigAndDepth() {
        val expires = Date(validExpiresMs)
        val certs = arrayOf(
            CertificateInfo(commonName1, fingerprint1, expires, 0),
            CertificateInfo(commonName1, fingerprint2, expires, 1),
            CertificateInfo(commonName2, fingerprint2, expires, 2)
        )
        val domainsConfig = DomainsConfig(
            sslPinningRequiredForUnlisted = false,
            domains = listOf(DomainConfig(name = commonName1, sslPinningRequired = true))
        )
        val cached = CachedData(certs, expires, domainsConfig)

        val json = CertStore.GSON.toJson(cached)
        val decoded = CertStore.GSON.fromJson(json, CachedData::class.java)

        assertNotNull(decoded)
        assertEquals(certs.size, decoded.certificates.size)
        assertEquals(0, decoded.certificates[0].depth)
        assertEquals(1, decoded.certificates[1].depth)
        assertEquals(2, decoded.certificates[2].depth)
        assertNotNull(decoded.domainsConfig)
        assertEquals(false, decoded.domainsConfig?.sslPinningRequiredForUnlisted)
        assertEquals(1, decoded.domainsConfig?.domains?.size)
        assertEquals(commonName1, decoded.domainsConfig?.domains?.first()?.name)
        assertEquals(true, decoded.domainsConfig?.domains?.first()?.sslPinningRequired)
    }

    /**
     * Tests that [CachedData] without [DomainsConfig] serialises and deserialises correctly
     * (backward compatibility with cache entries that pre-date domainsConfig).
     */
    @Test
    fun testCachedData_SerializationWithoutDomainsConfig() {
        val expires = Date(validExpiresMs)
        val certs = arrayOf(CertificateInfo(commonName1, fingerprint1, expires, 0))
        val cached = CachedData(certs, expires, null)

        val json = CertStore.GSON.toJson(cached)
        val decoded = CertStore.GSON.fromJson(json, CachedData::class.java)

        assertNotNull(decoded)
        assertNull(decoded.domainsConfig)
        assertEquals(0, decoded.certificates.first().depth)
    }
}
