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

package com.wultra.android.sslpinning;

import com.wultra.android.sslpinning.model.GetFingerprintResponse;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.modules.junit4.PowerMockRunner;

import java.net.URL;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;
import java.util.concurrent.TimeUnit;

import static org.junit.Assert.assertEquals;

/**
 * Tests for validation with [CertStore].
 *
 * @author Tomas Kypta, tomas.kypta@wultra.com
 */
@RunWith(PowerMockRunner.class)
public class CertStoreValidationTest extends CommonJavaTest {

    @Test
    public void testValidationGithubFallbackValid() throws Exception {
        // necessary to update the fingerprint from time to time
        // Mar 2023 - "kqN/vV4hpTqVxxbhFE9EL1grlND6/Gc+tnF6TrUaiKc="
        validateGithubWithFallbackOnly("kqN/vV4hpTqVxxbhFE9EL1grlND6/Gc+tnF6TrUaiKc=", ValidationResult.TRUSTED);
    }

    @Test
    public void testValidationGithubFallbackInvalid() throws Exception {
        // outdated fingerprint
        validateGithubWithFallbackOnly("trmmrz6GbL4OajB+fdoXOzcrLTrD8GrxX5dxh3OEgAg=", ValidationResult.UNTRUSTED);
    }

    private void validateGithubWithFallbackOnly(String fingerprintBase64,
                                                ValidationResult expectedResult) throws Exception {
        X509Certificate cert = TestUtils.getCertificateFromUrl("https://github.com");

        String publicKey = "BC3kV9OIDnMuVoCdDR9nEA/JidJLTTDLuSA2TSZsGgODSshfbZg31MS90WC/HdbU/A5WL5GmyDkE/iks6INv+XE=";
        byte[] publicKeyBytes = Base64.getDecoder().decode(publicKey);

        String signatureBase64 = "MEUCICB69UpMPOdtrsR6XcJqHEh2L2RO4oSJ3SZ7BYnTBJbGAiEAnZ7rEWdMVGwa59Wx5QbAorEFxXH89Iu0CnqWa96Eda0=";
        byte[] signatureBytes = Base64.getDecoder().decode(signatureBase64);
        byte[] fingerprintBytes = Base64.getDecoder().decode(fingerprintBase64);

        GetFingerprintResponse.Entry fallbackEntry = new GetFingerprintResponse.Entry(
                "github.com",
                fingerprintBytes,
                new Date(System.currentTimeMillis() + TimeUnit.DAYS.toMillis(1)),
                signatureBytes);
        GetFingerprintResponse fallback = new GetFingerprintResponse(new GetFingerprintResponse.Entry[] {fallbackEntry});

        CertStoreConfiguration config = TestUtils.getCertStoreConfiguration(
                new Date(),
                new String[]{"github.com"},
                new URL("https://github.com"),
                publicKeyBytes,
                fallback);
        CertStore store = new CertStore(config, cryptoProvider, secureDataStore);
        TestUtils.assignHandler(store, handler);
        ValidationResult result = store.validateCertificate(cert);
        assertEquals(expectedResult, result);
    }

    @Test
    public void testValidationGithubUpdateWithOutdatedData() throws Exception {
        // json with outdated data, correct public key
        validateGithubWithUpdateJsonOnly("BC3kV9OIDnMuVoCdDR9nEA/JidJLTTDLuSA2TSZsGgODSshfbZg31MS90WC/HdbU/A5WL5GmyDkE/iks6INv+XE=",
                "https://gist.githubusercontent.com/hvge/7c5a3f9ac50332a52aa974d90ea2408c/raw/34866234bbaa3350dc0ddc5680a65a6f4e7c549e/ssl-pinning-signatures.json",
                UpdateResult.STORE_IS_EMPTY, ValidationResult.EMPTY);
    }
    @Test
    public void testValidationGithubUpdateWithInvalidSignature() throws Exception {
        // json with current data, different public key
        validateGithubWithUpdateJsonOnly("BC3kV9OIDnMuVoCdDR9nEA/JidJLTTDLuSA2TSZsGgODSshfbZg31MS90WC/HdbU/A5WL5GmyDkE/iks6INv+XE=",
                "https://gist.githubusercontent.com/TomasKypta/40be50cc63d2f4c00abcbbf4554f0e32/raw/9cc9029d9e8248b0cd9a36b98382040114dd1d4a/ssl-pinning-signatures_Mar2023.json",
                UpdateResult.INVALID_SIGNATURE, ValidationResult.EMPTY);
    }

    @Test
    public void testValidationGithubUpdateWithValidData() throws Exception {
        // json with current data, correct public key
        validateGithubWithUpdateJsonOnly("BC3kV9OIDnMuVoCdDR9nEA/JidJLTTDLuSA2TSZsGgODSshfbZg31MS90WC/HdbU/A5WL5GmyDkE/iks6INv+XE=",
                "https://gist.githubusercontent.com/hvge/7c5a3f9ac50332a52aa974d90ea2408c/raw/07eb5b4b67e63d37d224912bc5951c7b589b35e6/ssl-pinning-signatures.json",
                UpdateResult.OK, ValidationResult.TRUSTED);
    }

    private void validateGithubWithUpdateJsonOnly(String publicKey,
                                                  String signaturesJsonUrl,
                                                  UpdateResult expectedUpdateResult,
                                                  ValidationResult expectedValidationResult) throws Exception {
        X509Certificate cert = TestUtils.getCertificateFromUrl("https://github.com");

        byte[] publicKeyBytes = Base64.getDecoder().decode(publicKey);

        CertStoreConfiguration config = TestUtils.getCertStoreConfiguration(
                new Date(),
                new String[]{"github.com"},
                new URL(signaturesJsonUrl),
                publicKeyBytes,
                null);
        CertStore store = new CertStore(config, cryptoProvider, secureDataStore);
        TestUtils.assignHandler(store, handler);
        TestUtils.updateAndCheck(store, UpdateMode.FORCED, expectedUpdateResult);

        ValidationResult result = store.validateCertificate(cert);
        assertEquals(expectedValidationResult, result);
    }
}
