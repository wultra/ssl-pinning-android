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

import android.support.annotation.NonNull;

import com.wultra.android.sslpinning.integration.DefaultUpdateObserver;
import com.wultra.android.sslpinning.interfaces.ECPublicKey;
import com.wultra.android.sslpinning.interfaces.SignedData;
import com.wultra.android.sslpinning.service.RemoteDataProvider;
import com.wultra.android.sslpinning.service.RemoteDataRequest;
import com.wultra.android.sslpinning.service.RemoteDataResponse;

import org.jetbrains.annotations.NotNull;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.modules.junit4.PowerMockRunner;

import java.net.URL;
import java.util.Base64;
import java.util.Date;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static java.util.Collections.emptyMap;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link CertStore} updates.
 *
 * @author Tomas Kypta, tomas.kypta@wultra.com
 */
@RunWith(PowerMockRunner.class)
public class CertStoreUpdateTest extends CommonJavaTest {

    @Test
    public void testCorrectUpdate() throws Exception {
        when(cryptoProvider.ecdsaValidateSignatures(any(SignedData.class), any(ECPublicKey.class)))
                .thenAnswer(invocation -> true);

        String pinningJsonUrl = "https://gist.githubusercontent.com/hvge/7c5a3f9ac50332a52aa974d90ea2408c/raw/34866234bbaa3350dc0ddc5680a65a6f4e7c549e/ssl-pinning-signatures.json";
        UpdateResult updateResult = performForcedUpdate(pinningJsonUrl);
        assertEquals(UpdateResult.OK, updateResult);
    }

    @Test
    public void testInvalidSignatureUpdate() throws Exception {
        when(cryptoProvider.ecdsaValidateSignatures(any(SignedData.class), any(ECPublicKey.class)))
                .thenAnswer(invocation -> false);

        String pinningJsonUrl = "https://gist.githubusercontent.com/hvge/7c5a3f9ac50332a52aa974d90ea2408c/raw/34866234bbaa3350dc0ddc5680a65a6f4e7c549e/ssl-pinning-signatures.json";
        UpdateResult updateResult = performForcedUpdate(pinningJsonUrl);
        assertEquals(UpdateResult.INVALID_SIGNATURE, updateResult);
    }

    @Test
    public void testExpiredUpdate() throws Exception {
        when(cryptoProvider.ecdsaValidateSignatures(any(SignedData.class), any(ECPublicKey.class)))
                .thenAnswer(invocation -> false);

        String pinningJsonUrl = "https://gist.githubusercontent.com/TomasKypta/5a6d99fe441a8c0d201b673d88e223a6/raw/0d12746cad1247ebf9a5b1706afabf8486a7a62e/ssl-pinning-signatures_expired.json";
        UpdateResult updateResult = performForcedUpdate(pinningJsonUrl);
        assertEquals(UpdateResult.STORE_IS_EMPTY, updateResult);
    }

    @Test
    public void testUpdateSignatureGithub() throws Exception {
        String publicKey = "BC3kV9OIDnMuVoCdDR9nEA/JidJLTTDLuSA2TSZsGgODSshfbZg31MS90WC/HdbU/A5WL5GmyDkE/iks6INv+XE=";
        byte[] publicKeyBytes = java.util.Base64.getDecoder().decode(publicKey);

        CertStoreConfiguration config = TestUtils.getCertStoreConfiguration(
                new Date(),
                new String[]{"github.com"},
                new URL("https://gist.githubusercontent.com/hvge/7c5a3f9ac50332a52aa974d90ea2408c/raw/34866234bbaa3350dc0ddc5680a65a6f4e7c549e/ssl-pinning-signatures.json"),
                publicKeyBytes,
                null);
        RemoteDataProvider remoteDataProvider = mock(RemoteDataProvider.class);
        String jsonData =
                "{\n" +
                        "  \"fingerprints\": [\n" +
                        "    {\n" +
                        "      \"name\" : \"github.com\",\n" +
                        "      \"fingerprint\" : \"trmmrz6GbL4OajB+fdoXOzcrLTrD8GrxX5dxh3OEgAg=\",\n" +
                        "      \"expires\" : 1652184000,\n" +
                        "      \"signature\" : \"MEUCIQCs1y/nyrKh4+2DIuX/PufUYiaVUdt2FBZQg6rBeZ/r4QIgNlT4owBwJ1ThrDsE0SwGipTNI74vP1vNyLNEwuXY4lE=\"\n" +
                        "    }\n" +
                        "  ]\n" +
                        "}";
        when(remoteDataProvider.getFingerprints(new RemoteDataRequest(emptyMap()))).thenReturn(new RemoteDataResponse(200, emptyMap(), jsonData.getBytes()));

        CertStore store = new CertStore(config, cryptoProvider, secureDataStore, remoteDataProvider);
        TestUtils.assignHandler(store, handler);
        TestUtils.updateAndCheck(store, UpdateMode.FORCED, UpdateResult.OK);
    }

    @Test
    public void testUpdateWithNoUpdateObserver() throws Exception {
        String publicKey = "BC3kV9OIDnMuVoCdDR9nEA/JidJLTTDLuSA2TSZsGgODSshfbZg31MS90WC/HdbU/A5WL5GmyDkE/iks6INv+XE=";
        byte[] publicKeyBytes = java.util.Base64.getDecoder().decode(publicKey);

        CertStoreConfiguration config = TestUtils.getCertStoreConfiguration(
                new Date(),
                new String[]{"github.com"},
                new URL("https://gist.githubusercontent.com/hvge/7c5a3f9ac50332a52aa974d90ea2408c/raw/c5b021db0fcd40b1262ab513bf375e4641834925/ssl-pinning-signatures.json"),
                publicKeyBytes,
                null);
        RemoteDataProvider remoteDataProvider = mock(RemoteDataProvider.class);
        String jsonData =
                "{\n" +
                        "  \"fingerprints\": [\n" +
                        "    {\n" +
                        "      \"name\" : \"github.com\",\n" +
                        "      \"fingerprint\" : \"trmmrz6GbL4OajB+fdoXOzcrLTrD8GrxX5dxh3OEgAg=\",\n" +
                        "      \"expires\" : 1652184000,\n" +
                        "      \"signature\" : \"MEUCIQCs1y/nyrKh4+2DIuX/PufUYiaVUdt2FBZQg6rBeZ/r4QIgNlT4owBwJ1ThrDsE0SwGipTNI74vP1vNyLNEwuXY4lE=\"\n" +
                        "    }\n" +
                        "  ]\n" +
                        "}";

        CountDownLatch latch = new CountDownLatch(1);
        when(remoteDataProvider.getFingerprints(new RemoteDataRequest(emptyMap()))).thenAnswer(
                invocation -> {
                    byte[] bytes = jsonData.getBytes();
                    latch.countDown();
                    return new RemoteDataResponse(200, emptyMap(), bytes);
                });

        CertStore store = new CertStore(config, cryptoProvider, secureDataStore, remoteDataProvider);
        TestUtils.assignHandler(store, handler);


        store.update(UpdateMode.FORCED, new DefaultUpdateObserver() {
            @Override
            public void onUpdateStarted(@NotNull UpdateType type) {
                assertEquals(UpdateType.DIRECT, type);
                super.onUpdateStarted(type);
            }

            @Override
            public void onUpdateFinished(@NotNull UpdateType type, @NotNull UpdateResult result) {
                assertEquals(UpdateType.DIRECT, type);
                super.onUpdateFinished(type, result);
            }

            @Override
            public void handleFailedUpdate(@NotNull UpdateType type, @NotNull UpdateResult result) {
                fail();
            }

            @Override
            public void continueExecution() {

            }
        });
        assertTrue(latch.await(2, TimeUnit.SECONDS));
    }

    @NonNull
    private UpdateResult performForcedUpdate(String pinningJsonUrl) throws Exception {
        String publicKey = "BC3kV9OIDnMuVoCdDR9nEA/JidJLTTDLuSA2TSZsGgODSshfbZg31MS90WC/HdbU/A5WL5GmyDkE/iks6INv+XE=";
        byte[] publicKeyBytes = Base64.getDecoder().decode(publicKey);

        CertStoreConfiguration config = TestUtils.getCertStoreConfiguration(
                new Date(),
                new String[]{"github.com"},
                new URL(pinningJsonUrl),
                publicKeyBytes,
                null);
        CertStore store = new CertStore(config, cryptoProvider, secureDataStore);
        TestUtils.assignHandler(store, handler);

        return TestUtils.updateAndCheck(store, UpdateMode.FORCED, null);
    }
}
