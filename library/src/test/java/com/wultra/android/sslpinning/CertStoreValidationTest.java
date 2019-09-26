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
    public void testValidationGithubFallback() throws Exception {
        X509Certificate cert = TestUtils.getCertificateFromUrl("https://github.com");

        String publicKey = "BEG6g28LNWRcmdFzexSNTKPBYZnDtKrCyiExFKbktttfKAF7wG4Cx1Nycr5PwCoICG1dRseLyuDxUilAmppPxAo=";
        byte[] publicKeyBytes = java.util.Base64.getDecoder().decode(publicKey);

        String signatureBase64 = "MEUCIQD8nGyux9GM8u3XCrRiuJj/N2eEuB0oiHzTEpGyy2gE9gIgYIRfyed6ykDzZbK1ougq1SoRW8UBe5q3VmWihHuL2JY=";
        byte[] signatureBytes = Base64.getDecoder().decode(signatureBase64);
        String fingerprintBase64 = "MRFQDEpmASza4zPsP8ocnd5FyVREDn7kE3Fr/zZjwHQ=";
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
        assertEquals(ValidationResult.TRUSTED, result);
    }

    @Test
    public void testValidationGithubUpdatedJson() throws Exception {
        X509Certificate cert = TestUtils.getCertificateFromUrl("https://github.com");

        String publicKey = "BC3kV9OIDnMuVoCdDR9nEA/JidJLTTDLuSA2TSZsGgODSshfbZg31MS90WC/HdbU/A5WL5GmyDkE/iks6INv+XE=";
        byte[] publicKeyBytes = java.util.Base64.getDecoder().decode(publicKey);

        CertStoreConfiguration config = TestUtils.getCertStoreConfiguration(
                new Date(),
                new String[]{"github.com"},
                new URL("https://gist.githubusercontent.com/hvge/7c5a3f9ac50332a52aa974d90ea2408c/raw/c5b021db0fcd40b1262ab513bf375e4641834925/ssl-pinning-signatures.json"),
                publicKeyBytes,
                null);
        CertStore store = new CertStore(config, cryptoProvider, secureDataStore);
        TestUtils.assignHandler(store, handler);
        TestUtils.updateAndCheck(store, UpdateMode.FORCED, UpdateResult.OK);

        ValidationResult result = store.validateCertificate(cert);
        assertEquals(ValidationResult.TRUSTED, result);
    }
}
