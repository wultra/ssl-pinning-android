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

import android.content.Context;

import com.wultra.android.sslpinning.CertStore;
import com.wultra.android.sslpinning.CertStoreConfiguration;
import com.wultra.android.sslpinning.integration.powerauth.PowerAuthCertStore;
import com.wultra.android.sslpinning.integration.powerauth.PowerAuthIntegrationKt;
import com.wultra.android.sslpinning.integration.powerauth.PowerAuthSecureDataStore;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.net.URL;

/**
 * Testing format of Java compatible APIs.
 *
 * @author Tomas Kypta, tomas.kypta@wultra.com
 */
@RunWith(MockitoJUnitRunner.class)
public class PowerAuthIntegrationTest {

    @Mock
    Context context;

    @Test
    public void testPowerAuthCertStoreApis() throws Exception {
        URL url = new URL("https://gist.githubusercontent.com/hvge/7c5a3f9ac50332a52aa974d90ea2408c/raw/c5b021db0fcd40b1262ab513bf375e4641834925/ssl-pinning-signatures.json");
        String publicKey = "BC3kV9OIDnMuVoCdDR9nEA/JidJLTTDLuSA2TSZsGgODSshfbZg31MS90WC/HdbU/A5WL5GmyDkE/iks6INv+XE=";
        byte[] publicKeyBytes = java.util.Base64.getDecoder().decode(publicKey);

        CertStoreConfiguration configuration = new CertStoreConfiguration.Builder(url, publicKeyBytes)
                .build();
        CertStore store1 = PowerAuthCertStore.Companion.createInstance(configuration, context, null);
        Assert.assertNotNull(store1);
        CertStore store2 = PowerAuthCertStore.createInstance(configuration, context, null);
        Assert.assertNotNull(store2);
        CertStore store3 = PowerAuthCertStore.createInstance(configuration, context);
        Assert.assertNotNull(store3);

        // Kotlin API inconvenient for calling from Java
        CertStore store4 = PowerAuthIntegrationKt.powerAuthCertStore(CertStore.Companion, configuration, context, "");
        Assert.assertNotNull(store4);
    }

    @Test
    public void testPowerAuthSecureDataStoreApis() {
        PowerAuthSecureDataStore secureDataStore1 = new PowerAuthSecureDataStore(context, "");
        Assert.assertNotNull(secureDataStore1);
        PowerAuthSecureDataStore secureDataStore2 = new PowerAuthSecureDataStore(context);
        Assert.assertNotNull(secureDataStore2);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testPowerAuthSecureDataStoreApisCrash() {
        new PowerAuthSecureDataStore(context, null);
    }
}
