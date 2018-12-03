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

import android.content.Context;
import android.support.test.InstrumentationRegistry;

import com.wultra.android.sslpinning.integration.powerauth.PowerAuthCertStore;
import com.wultra.android.sslpinning.integration.powerauth.PowerAuthCryptoProvider;
import com.wultra.android.sslpinning.integration.powerauth.PowerAuthSecureDataStore;

import org.junit.Test;

import java.net.URL;

import static com.wultra.android.sslpinning.TestUtilsKt.jsonDataAllEmpty;
import static com.wultra.android.sslpinning.TestUtilsKt.jsonDataFingerprintsEmpty;
import static com.wultra.android.sslpinning.TestUtilsKt.getPublicKeyBytes;
import static com.wultra.android.sslpinning.TestUtilsKt.getRemoteDataProvider;
import static com.wultra.android.sslpinning.TestUtilsKt.updateAndCheck;

/**
 * Instrumentation test for update signature validation on a device/emulator.
 * Written in Java to validate APIs.
 *
 * @author Tomas Kypta, tomas.kypta@wultra.com
 */
public class CertStoreUpdateTestJava {


    @Test
    public void testLocalUpdateSignatureGithub_InvalidUrlUpdate() throws Exception {
        Context appContext = InstrumentationRegistry.getTargetContext();

        // empty
        URL url = new URL("https://gist.githubusercontent.com/TomasKypta/ae4fa795a8c1ffa1ed0144c49b95e63c/raw/761483b6c1fa3039f0b9d7b05c5d43532fc1556a/ssl-pinning-signatures_invalid_url.json");
        CertStoreConfiguration config = new CertStoreConfiguration.Builder(url, getPublicKeyBytes()).build();
        CertStore store = PowerAuthCertStore.createInstance(config, appContext);

        updateAndCheck(store, UpdateMode.FORCED, UpdateResult.NETWORK_ERROR);
    }

    @Test
    public void testLocalUpdateSignatureGithub_EmptyUpdate() throws Exception {
        Context appContext = InstrumentationRegistry.getTargetContext();

        // empty
        URL url = new URL("https://gist.githubusercontent.com/TomasKypta/ae4fa795a8c1ffa1ed0144c49b95e63c/raw/761483b6c1fa3039f0b9d7b05c5d43532fc1556a/ssl-pinning-signatures_empty.json");
        CertStoreConfiguration config = new CertStoreConfiguration.Builder(url, getPublicKeyBytes()).build();
        CertStore store = new CertStore(config, new PowerAuthCryptoProvider(), new PowerAuthSecureDataStore(appContext), getRemoteDataProvider(jsonDataAllEmpty));

        updateAndCheck(store, UpdateMode.FORCED, UpdateResult.INVALID_DATA);
    }

    @Test
    public void testLocalUpdateSignatureGithub_EmptyFingerprintUpdate() throws Exception {
        Context appContext = InstrumentationRegistry.getTargetContext();

        // empty
        URL url = new URL("https://gist.githubusercontent.com/TomasKypta/ae4fa795a8c1ffa1ed0144c49b95e63c/raw/761483b6c1fa3039f0b9d7b05c5d43532fc1556a/ssl-pinning-signatures_empty.json");
        CertStoreConfiguration config = new CertStoreConfiguration.Builder(url, getPublicKeyBytes()).build();
        CertStore store = new CertStore(config, new PowerAuthCryptoProvider(), new PowerAuthSecureDataStore(appContext), getRemoteDataProvider(jsonDataFingerprintsEmpty));

        updateAndCheck(store, UpdateMode.FORCED, UpdateResult.STORE_IS_EMPTY);
    }

    @Test
    public void testRemoteUpdateSignatureGithub_EmptyUpdate() throws Exception {
        Context appContext = InstrumentationRegistry.getTargetContext();

        // empty
        URL url = new URL("https://gist.githubusercontent.com/TomasKypta/ae4fa795a8c1ffa1ed0144c49b95e63c/raw/761483b6c1fa3039f0b9d7b05c5d43532fc1556a/ssl-pinning-signatures_empty.json");
        CertStoreConfiguration config = new CertStoreConfiguration.Builder(url, getPublicKeyBytes()).build();
        CertStore store = PowerAuthCertStore.createInstance(config, appContext);

        updateAndCheck(store, UpdateMode.FORCED, UpdateResult.STORE_IS_EMPTY);
    }
}
