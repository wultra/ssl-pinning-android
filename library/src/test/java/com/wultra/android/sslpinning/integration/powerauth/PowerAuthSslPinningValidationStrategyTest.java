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

package com.wultra.android.sslpinning.integration.powerauth;

import com.wultra.android.sslpinning.CertStore;
import com.wultra.android.sslpinning.CertStoreConfiguration;
import com.wultra.android.sslpinning.CommonJavaTest;
import com.wultra.android.sslpinning.TestUtils;
import com.wultra.android.sslpinning.UpdateMode;
import com.wultra.android.sslpinning.UpdateResult;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.modules.junit4.PowerMockRunner;

import java.net.URL;
import java.net.URLConnection;
import java.util.Date;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLSocketFactory;

import io.getlime.security.powerauth.networking.ssl.HttpClientValidationStrategy;

import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/**
 * Unit test for PowerAuthSslPinningValidationStrategy.
 *
 * @author Tomas Kypta, tomas.kypta@wultra.com
 */
@RunWith(PowerMockRunner.class)
public class PowerAuthSslPinningValidationStrategyTest extends CommonJavaTest {

    @Test
    public void testPowerAuthSslPinningValidationStrategyOnGithubSuccess() throws Exception {
        String publicKey = "BC3kV9OIDnMuVoCdDR9nEA/JidJLTTDLuSA2TSZsGgODSshfbZg31MS90WC/HdbU/A5WL5GmyDkE/iks6INv+XE=";
        byte[] publicKeyBytes = java.util.Base64.getDecoder().decode(publicKey);

        CertStoreConfiguration config = TestUtils.getCertStoreConfiguration(
                new Date(),
                new String[]{"github.com"},
                new URL("https://gist.githubusercontent.com/hvge/7c5a3f9ac50332a52aa974d90ea2408c/raw/07eb5b4b67e63d37d224912bc5951c7b589b35e6/ssl-pinning-signatures.json"),
                publicKeyBytes,
                null);
        CertStore store = new CertStore(config, cryptoProvider, secureDataStore);
        TestUtils.assignHandler(store, handler);
        TestUtils.updateAndCheck(store, UpdateMode.FORCED, UpdateResult.OK);

        HttpClientValidationStrategy strategy = new PowerAuthSslPinningValidationStrategy(store);

        URL url = new URL("https://github.com");
        URLConnection urlConnection = url.openConnection();
        final HttpsURLConnection sslConnection = (HttpsURLConnection) urlConnection;
        final SSLSocketFactory sslSocketFactory = strategy.getSSLSocketFactory();
        if (sslSocketFactory != null) {
            sslConnection.setSSLSocketFactory(sslSocketFactory);
        }
        final HostnameVerifier hostnameVerifier = strategy.getHostnameVerifier();
        if (hostnameVerifier != null) {
            sslConnection.setHostnameVerifier(hostnameVerifier);
        }

        verify(cryptoProvider, times(0)).hashSha256(any(byte[].class));

        sslConnection.connect();
        int response = sslConnection.getResponseCode();
        assertEquals(2, response / 100);
        sslConnection.disconnect();

        verify(cryptoProvider, times(1)).hashSha256(any(byte[].class));
        verify(secureDataStore).load(anyString());
    }

    @Test(expected = SSLHandshakeException.class)
    public void testPowerAuthSslPinningValidationStrategyOnGithubFailure() throws Exception {
        String publicKey = "BC3kV9OIDnMuVoCdDR9nEA/JidJLTTDLuSA2TSZsGgODSshfbZg31MS90WC/HdbU/A5WL5GmyDkE/iks6INv+XE=";
        byte[] publicKeyBytes = java.util.Base64.getDecoder().decode(publicKey);

        CertStoreConfiguration config = TestUtils.getCertStoreConfiguration(
                new Date(),
                new String[]{"github.com"},
                new URL("https://test.wultra.com"),
                publicKeyBytes,
                null);
        CertStore store = new CertStore(config, cryptoProvider, secureDataStore);
        TestUtils.assignHandler(store, handler);

        HttpClientValidationStrategy strategy = new PowerAuthSslPinningValidationStrategy(store);

        URL url = new URL("https://github.com");
        URLConnection urlConnection = url.openConnection();
        final HttpsURLConnection sslConnection = (HttpsURLConnection) urlConnection;
        final SSLSocketFactory sslSocketFactory = strategy.getSSLSocketFactory();
        if (sslSocketFactory != null) {
            sslConnection.setSSLSocketFactory(sslSocketFactory);
        }
        final HostnameVerifier hostnameVerifier = strategy.getHostnameVerifier();
        if (hostnameVerifier != null) {
            sslConnection.setHostnameVerifier(hostnameVerifier);
        }

        verify(cryptoProvider, times(0)).hashSha256(any(byte[].class));

        sslConnection.connect();
    }
}
