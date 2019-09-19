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

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.concurrent.TimeUnit;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

/**
 * @author Tomas Kypta, tomas.kypta@wultra.com
 */
@RunWith(PowerMockRunner.class)
public class CertStoreConfigurationTest extends CommonJavaTest {

    @Test
    public void testBasicConfiguration() throws Exception {
        String serviceUrl = "https://test.wultra.com";
        CertStoreConfiguration.Builder builder = new CertStoreConfiguration.Builder(
                        new URL(serviceUrl), "aaa".getBytes())
                .expectedCommonNames(new String[]{"Test", "Wultra"});
        CertStoreConfiguration config = builder.build();
        assertEquals(serviceUrl, config.getServiceUrl().toString());
        assertEquals("aaa", new String(config.getPublicKey()));
    }

    @Test
    public void testConfiguration() throws Exception {
        CertStoreConfiguration config = configuration(new Date());
        assertNull(config.getFallbackCertificates());
        CertStore store = new CertStore(config, cryptoProvider, secureDataStore);
        TestUtils.assignHandler(store, handler);

        byte[] fingerprint = new byte[32];
        Arrays.fill(fingerprint, (byte)0xff);
        ValidationResult result = store.validateFingerprint("api.fallback.org", fingerprint);
        assertEquals(ValidationResult.EMPTY, result);
    }

    @Test
    public void testConfigurationWithFallbackCertificate() throws Exception {
        CertStoreConfiguration config = configurationWithFallback(null, null);
        assertNotNull(config.getFallbackCertificates());
        CertStore store = new CertStore(config, cryptoProvider, secureDataStore);
        TestUtils.assignHandler(store, handler);

        byte[] fingerprint = new byte[32];
        Arrays.fill(fingerprint, (byte)0xff);
        ValidationResult result = store.validateFingerprint("api.fallback.org", fingerprint);
        assertEquals(ValidationResult.TRUSTED, result);
    }

    @Test
    public void testConfigurationWithFallbackCertificateExpired() throws Exception {
        Date expired = new Date(new Date().getTime() - TimeUnit.SECONDS.toMillis(1));
        CertStoreConfiguration config = configurationWithFallback(expired, null);
        assertNotNull(config.getFallbackCertificates());
        CertStore store = new CertStore(config, cryptoProvider, secureDataStore);
        TestUtils.assignHandler(store, handler);

        byte[] fingerprint = new byte[32];
        Arrays.fill(fingerprint, (byte)0xff);
        ValidationResult result = store.validateFingerprint("api.fallback.org", fingerprint);
        assertEquals(ValidationResult.EMPTY, result);
    }

    @Test
    public void testConfigurationWithNonMatchingExpectedCommonNames() throws Exception {
        CertStoreConfiguration config = configurationWithFallback(null, new String[]{"www.wultra.com"});
        CertStore store = new CertStore(config, cryptoProvider, secureDataStore);
        TestUtils.assignHandler(store, handler);

        byte[] fingerprint = new byte[32];
        Arrays.fill(fingerprint, (byte)0xff);
        ValidationResult result = store.validateFingerprint("api.fallback.org", fingerprint);
        assertEquals("Validate non-matching common name", ValidationResult.UNTRUSTED, result);

        result = store.validateFingerprint("www.wultra.com", fingerprint);
        assertEquals("Validate matching common name, no matching fingerprint", ValidationResult.EMPTY, result);
    }

    @Test
    public void testConfigurationWithMatchingExpectedCommonNames() throws Exception {
        CertStoreConfiguration config = configurationWithFallback(null, new String[]{"api.fallback.org"});
        CertStore store = new CertStore(config, cryptoProvider, secureDataStore);
        TestUtils.assignHandler(store, handler);

        byte[] fingerprint = new byte[32];
        Arrays.fill(fingerprint, (byte)0xff);
        ValidationResult result = store.validateFingerprint("api.fallback.org", fingerprint);
        assertEquals("Validate matching common name", ValidationResult.TRUSTED, result);

        result = store.validateFingerprint("www.wultra.com", fingerprint);
        assertEquals("Validate non-matching common name", ValidationResult.UNTRUSTED, result);
    }

    private CertStoreConfiguration configuration(Date expiration) throws MalformedURLException {
        if (expiration == null) {
            // create valid date
            expiration = new Date(new Date().getTime() + TimeUnit.SECONDS.toMillis(10));
        }
        URL serviceUrl = new URL("https://foo.wultra.com");
        String publicKey = "BEG6g28LNWRcmdFzexSNTKPBYZnDtKrCyiExFKbktttfKAF7wG4Cx1Nycr5PwCoICG1dRseLyuDxUilAmppPxAo=";
        byte[] publicKeyBytes = java.util.Base64.getDecoder().decode(publicKey);
        return TestUtils.getCertStoreConfiguration(expiration, null, serviceUrl, publicKeyBytes, null);
    }

    private CertStoreConfiguration configurationWithFallback(Date expiration, String[] expectedCommonNames) throws MalformedURLException {
        if (expiration == null) {
            // create valid date
            expiration = new Date(new Date().getTime() + TimeUnit.SECONDS.toMillis(10));
        }
        URL serviceUrl = new URL("https://foo.wultra.com");
        String publicKey = "BEG6g28LNWRcmdFzexSNTKPBYZnDtKrCyiExFKbktttfKAF7wG4Cx1Nycr5PwCoICG1dRseLyuDxUilAmppPxAo=";
        byte[] publicKeyBytes = java.util.Base64.getDecoder().decode(publicKey);

        byte[] fingerprint = new byte[32];
        Arrays.fill(fingerprint, (byte)0xff);
        byte[] signature = new byte[64];
        Arrays.fill(signature, (byte)0xfe);

        GetFingerprintResponse.Entry[] fallbackList = new GetFingerprintResponse.Entry[] { new GetFingerprintResponse.Entry("api.fallback.org", fingerprint, expiration, signature) };
        GetFingerprintResponse fallbackData = new GetFingerprintResponse(fallbackList);

        return TestUtils.getCertStoreConfiguration(expiration, expectedCommonNames, serviceUrl, publicKeyBytes, fallbackData);
    }

}
