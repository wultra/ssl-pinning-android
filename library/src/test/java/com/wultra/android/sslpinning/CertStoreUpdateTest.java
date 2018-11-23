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

import com.wultra.android.sslpinning.integration.powerauth.PA2ECPublicKey;
import com.wultra.android.sslpinning.interfaces.CryptoProvider;
import com.wultra.android.sslpinning.interfaces.ECPublicKey;
import com.wultra.android.sslpinning.interfaces.SignedData;
import com.wultra.android.sslpinning.service.RemoteDataProvider;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.modules.junit4.PowerMockRunner;

import java.net.URL;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Date;

import io.getlime.security.powerauth.crypto.lib.config.PowerAuthConfiguration;
import io.getlime.security.powerauth.crypto.lib.util.SignatureUtils;
import io.getlime.security.powerauth.provider.CryptoProviderUtil;

import static org.junit.Assert.assertEquals;
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
                .thenAnswer(invocation -> {
                    return true;
                });

        String pinningJsonUrl = "https://gist.githubusercontent.com/hvge/7c5a3f9ac50332a52aa974d90ea2408c/raw/c5b021db0fcd40b1262ab513bf375e4641834925/ssl-pinning-signatures.json";
        UpdateResult updateResult = performForcedUpdate(pinningJsonUrl);
        assertEquals(UpdateResult.OK, updateResult);
    }

    @Test
    public void testInvalidSignatureUpdate() throws Exception {
        when(cryptoProvider.ecdsaValidateSignatures(any(SignedData.class), any(ECPublicKey.class)))
                .thenAnswer(invocation -> {
                    return false;
                });

        String pinningJsonUrl = "https://gist.githubusercontent.com/hvge/7c5a3f9ac50332a52aa974d90ea2408c/raw/c5b021db0fcd40b1262ab513bf375e4641834925/ssl-pinning-signatures.json";
        UpdateResult updateResult = performForcedUpdate(pinningJsonUrl);
        assertEquals(UpdateResult.INVALID_SIGNATURE, updateResult);
    }

    @Test
    public void testExpiredUpdate() throws Exception {
        when(cryptoProvider.ecdsaValidateSignatures(any(SignedData.class), any(ECPublicKey.class)))
                .thenAnswer(invocation -> {
                    return false;
                });

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
                new URL("https://gist.githubusercontent.com/hvge/7c5a3f9ac50332a52aa974d90ea2408c/raw/c5b021db0fcd40b1262ab513bf375e4641834925/ssl-pinning-signatures.json"),
                publicKeyBytes,
                null);
        RemoteDataProvider remoteDataProvider = mock(RemoteDataProvider.class);
        String jsonData =
                "{\n" +
                        "  \"fingerprints\": [\n" +
                        "    {\n" +
                        "      \"name\" : \"github.com\",\n" +
                        "      \"fingerprint\" : \"MRFQDEpmASza4zPsP8ocnd5FyVREDn7kE3Fr/zZjwHQ=\",\n" +
                        "      \"expires\" : 1591185600,\n" +
                        "      \"signature\" : \"MEUCIQD8nGyux9GM8u3XCrRiuJj/N2eEuB0oiHzTEpGyy2gE9gIgYIRfyed6ykDzZbK1ougq1SoRW8UBe5q3VmWihHuL2JY=\"\n" +
                        "    }\n" +
                        "  ]\n" +
                        "}";
        when(remoteDataProvider.getFingerprints()).thenReturn(jsonData.getBytes());

        CryptoProvider cryptoProvider = mock(CryptoProvider.class);
        when(cryptoProvider.hashSha256(any(byte[].class)))
                .thenAnswer(invocation -> {
                    MessageDigest digest = MessageDigest.getInstance("SHA-256");
                    return digest.digest(invocation.getArgument(0));
                });
        when(cryptoProvider.importECPublicKey(any(byte[].class)))
                .thenAnswer(invocation ->
                        new PA2ECPublicKey(invocation.getArgument(0))
                );
        when(cryptoProvider.ecdsaValidateSignatures(any(SignedData.class), any(ECPublicKey.class)))
                .thenAnswer(invocation -> {
                    SignatureUtils utils = new SignatureUtils();
                    SignedData signedData = invocation.getArgument(0);
                    PA2ECPublicKey pubKey = invocation.getArgument(1);
                    final CryptoProviderUtil keyConvertor = PowerAuthConfiguration.INSTANCE.getKeyConvertor();
                    return utils.validateECDSASignature(signedData.getData(),
                            signedData.getSignature(),
                            keyConvertor.convertBytesToPublicKey(pubKey.getData()));
                });

        CertStore store = new CertStore(config, cryptoProvider, secureDataStore, remoteDataProvider);
        TestUtils.assignHandler(store, handler);
        TestUtils.updateAndCheck(store, UpdateMode.FORCED, UpdateResult.OK);
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
