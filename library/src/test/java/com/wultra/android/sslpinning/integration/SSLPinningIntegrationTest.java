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

package com.wultra.android.sslpinning.integration;

import com.wultra.android.sslpinning.CertStore;
import com.wultra.android.sslpinning.CertStoreConfiguration;
import com.wultra.android.sslpinning.CommonKotlinTest;
import com.wultra.android.sslpinning.TestUtils;
import com.wultra.android.sslpinning.integration.powerauth.PowerAuthCertStore;

import org.junit.Assert;
import org.junit.Test;

import java.net.URL;

import javax.net.ssl.SSLSocketFactory;

/**
 * Testing format of Java compatible APIs.
 *
 * @author Tomas Kypta, tomas.kypta@wultra.com
 */
public class SSLPinningIntegrationTest extends CommonKotlinTest {

    @Test
    public void testSSLPinningIntegrationApis() throws Exception {
        URL url = new URL("https://gist.githubusercontent.com/hvge/7c5a3f9ac50332a52aa974d90ea2408c/raw/c5b021db0fcd40b1262ab513bf375e4641834925/ssl-pinning-signatures.json");
        String publicKey = "BC3kV9OIDnMuVoCdDR9nEA/JidJLTTDLuSA2TSZsGgODSshfbZg31MS90WC/HdbU/A5WL5GmyDkE/iks6INv+XE=";
        byte[] publicKeyBytes = java.util.Base64.getDecoder().decode(publicKey);

        CertStoreConfiguration configuration = new CertStoreConfiguration.Builder(url, publicKeyBytes)
                .build();
        CertStore store = PowerAuthCertStore.createInstance(configuration, context);
        TestUtils.assignHandler(store, handler);

        Assert.assertNotNull(store);

        SSLSocketFactory factory1 = SSLPinningIntegration.createSSLPinningSocketFactory(store);
        Assert.assertNotNull(factory1);

        SSLPinningX509TrustManager trustManager = new SSLPinningX509TrustManager(store);
        SSLSocketFactory factory2 = SSLPinningIntegration.createSSLPinningSocketFactory(trustManager);
        Assert.assertNotNull(factory2);
    }
}
