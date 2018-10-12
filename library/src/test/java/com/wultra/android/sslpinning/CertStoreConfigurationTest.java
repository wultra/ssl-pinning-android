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

import android.util.Base64;
import android.util.Log;

import com.wultra.android.sslpinning.interfaces.CryptoProvider;
import com.wultra.android.sslpinning.interfaces.SecureDataStore;
import com.wultra.android.sslpinning.model.GetFingerprintResponse;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Arrays;
import java.util.Date;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

/**
 * @author Tomas Kypta, tomas.kypta@wultra.com
 */
@RunWith(PowerMockRunner.class)
@PrepareForTest({
        Base64.class,
        Log.class
})
public class CertStoreConfigurationTest {

    @Mock
    CryptoProvider cryptoProvider;

    @Mock
    SecureDataStore secureDataStore;

    @Before
    public void setUp() {
        PowerMockito.mockStatic(Base64.class);
        when(Base64.encodeToString(any(byte[].class), anyInt()))
                .thenAnswer(invocation ->
                        new String(java.util.Base64.getEncoder().encode((byte[]) invocation.getArgument(0)))
                );

        PowerMockito.mockStatic(Log.class);
        when(Log.e(anyString(), anyString()))
                .then(invocation -> {
                    System.out.println((String) invocation.getArgument(1));
                    return 0;
                });
    }

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
        assertNull(config.getFallbackCertificate());
        CertStore store = new CertStore(config, cryptoProvider, secureDataStore);

        byte[] fingerprint = new byte[32];
        Arrays.fill(fingerprint, (byte)0xff);
        ValidationResult result = store.validateFingerprint("api.fallback.org", fingerprint);
        assertEquals(ValidationResult.EMPTY, result);
    }

    @Test
    public void testConfigurationWithFallbackCertificate() throws Exception {
        CertStoreConfiguration config = configurationWithFallback(new Date(), null);
        assertNotNull(config.getFallbackCertificate());
        CertStore store = new CertStore(config, cryptoProvider, secureDataStore);

        byte[] fingerprint = new byte[32];
        Arrays.fill(fingerprint, (byte)0xff);
        ValidationResult result = store.validateFingerprint("api.fallback.org", fingerprint);
        // TODO it should not be trusted the fingerprint is expired
        assertEquals(ValidationResult.TRUSTED, result);
    }

    @Test
    public void testConfigurationWithNonMatchingExpectedCommonNames() throws Exception {
        CertStoreConfiguration config = configurationWithFallback(new Date(), new String[]{"www.wultra.com"});
        CertStore store = new CertStore(config, cryptoProvider, secureDataStore);

        byte[] fingerprint = new byte[32];
        Arrays.fill(fingerprint, (byte)0xff);
        ValidationResult result = store.validateFingerprint("api.fallback.org", fingerprint);
        assertEquals("Validate non-matching common name", ValidationResult.UNTRUSTED, result);

        result = store.validateFingerprint("www.wultra.com", fingerprint);
        assertEquals("Validate matching common name, no matching fingerprint", ValidationResult.EMPTY, result);
    }

    @Test
    public void testConfigurationWithMatchingExpectedCommonNames() throws Exception {
        CertStoreConfiguration config = configurationWithFallback(new Date(), new String[]{"api.fallback.org"});
        CertStore store = new CertStore(config, cryptoProvider, secureDataStore);

        byte[] fingerprint = new byte[32];
        Arrays.fill(fingerprint, (byte)0xff);
        ValidationResult result = store.validateFingerprint("api.fallback.org", fingerprint);
        assertEquals("Validate matching common name", ValidationResult.TRUSTED, result);

        result = store.validateFingerprint("www.wultra.com", fingerprint);
        assertEquals("Validate non-matching common name", ValidationResult.UNTRUSTED, result);
    }

    private CertStoreConfiguration configuration(Date expiration) throws MalformedURLException {
        URL serviceUrl = new URL("https://foo.wultra.com");
        String publicKey = "BEG6g28LNWRcmdFzexSNTKPBYZnDtKrCyiExFKbktttfKAF7wG4Cx1Nycr5PwCoICG1dRseLyuDxUilAmppPxAo=";

        CertStoreConfiguration.Builder builder = new CertStoreConfiguration.Builder(
                serviceUrl, publicKey.getBytes())
                .identifier(null);
        return builder.build();
    }

    private CertStoreConfiguration configurationWithFallback(Date expiration, String[] expectedCommonNames) throws MalformedURLException {
        URL serviceUrl = new URL("https://foo.wultra.com");
        String publicKey = "BEG6g28LNWRcmdFzexSNTKPBYZnDtKrCyiExFKbktttfKAF7wG4Cx1Nycr5PwCoICG1dRseLyuDxUilAmppPxAo=";

        byte[] fingerprint = new byte[32];
        Arrays.fill(fingerprint, (byte)0xff);
        byte[] signature = new byte[64];
        Arrays.fill(signature, (byte)0xfe);

        GetFingerprintResponse.Entry fallbackData = new GetFingerprintResponse.Entry(
                "api.fallback.org", fingerprint, expiration, signature);

        CertStoreConfiguration.Builder builder = new CertStoreConfiguration.Builder(
                serviceUrl, publicKey.getBytes())
                .identifier(null)
                .expectedCommonNames(expectedCommonNames)
                .fallbackCertificate(fallbackData);
        return builder.build();
    }
}
