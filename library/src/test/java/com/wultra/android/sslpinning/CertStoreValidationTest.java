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

import android.util.Log;

import com.wultra.android.sslpinning.interfaces.CryptoProvider;
import com.wultra.android.sslpinning.interfaces.ECPublicKey;
import com.wultra.android.sslpinning.interfaces.SecureDataStore;
import com.wultra.android.sslpinning.interfaces.SignedData;
import com.wultra.android.sslpinning.model.GetFingerprintResponse;
import com.wultra.android.sslpinning.integration.powerauth.PA2ECPublicKey;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import java.net.URL;
import java.security.MessageDigest;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;
import java.util.concurrent.TimeUnit;

import io.getlime.security.powerauth.crypto.lib.config.PowerAuthConfiguration;
import io.getlime.security.powerauth.crypto.lib.util.SignatureUtils;
import io.getlime.security.powerauth.provider.CryptoProviderUtil;
import io.getlime.security.powerauth.provider.CryptoProviderUtilBouncyCastle;

import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

/**
 * @author Tomas Kypta, tomas.kypta@wultra.com
 */
@RunWith(PowerMockRunner.class)
@PowerMockIgnore({
        "javax.net.ssl.*",
        "javax.security.auth.x500.*",
        "org.bouncycastle.*",
        "java.security.*"
})
@PrepareForTest({
        android.util.Base64.class,
        Log.class
})
public class CertStoreValidationTest {

    @Mock
    CryptoProvider cryptoProvider;

    @Mock
    SecureDataStore secureDataStore;

    @BeforeClass
    public static void setUpClass() {
        Security.addProvider(new BouncyCastleProvider());
        PowerAuthConfiguration.INSTANCE.setKeyConvertor(new CryptoProviderUtilBouncyCastle());
    }

    @Before
    public void setUp() {
        PowerMockito.mockStatic(android.util.Base64.class);
        when(android.util.Base64.encodeToString(any(byte[].class), anyInt()))
                .thenAnswer(invocation ->
                        new String(java.util.Base64.getEncoder().encode((byte[]) invocation.getArgument(0)))
                );
        when(android.util.Base64.encode(any(byte[].class), anyInt()))
                .thenAnswer(invocation ->
                        java.util.Base64.getEncoder().encode((byte[]) invocation.getArgument(0))
                );
        when(android.util.Base64.decode(anyString(), anyInt()))
                .thenAnswer(invocation ->
                        Base64.getDecoder().decode((String)invocation.getArgument(0))
                );

        PowerMockito.mockStatic(Log.class);
        when(Log.e(anyString(), anyString()))
                .then(invocation -> {
                    System.out.println((String) invocation.getArgument(1));
                    return 0;
                });
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
    }

    @Test
    public void testValidationGithubFallback() throws Exception {
        X509Certificate cert = TestUtils.getCertificateFromUrl("https://github.com");

        String publicKey = "BEG6g28LNWRcmdFzexSNTKPBYZnDtKrCyiExFKbktttfKAF7wG4Cx1Nycr5PwCoICG1dRseLyuDxUilAmppPxAo=";
        byte[] publicKeyBytes = java.util.Base64.getDecoder().decode(publicKey);

        String signatureBase64 = "MEUCIQD8nGyux9GM8u3XCrRiuJj/N2eEuB0oiHzTEpGyy2gE9gIgYIRfyed6ykDzZbK1ougq1SoRW8UBe5q3VmWihHuL2JY=";
        byte[] signatureBytes = Base64.getDecoder().decode(signatureBase64);
        String fingerprintBase64 = "MRFQDEpmASza4zPsP8ocnd5FyVREDn7kE3Fr/zZjwHQ=";
        byte[] fingerprintBytes = Base64.getDecoder().decode(fingerprintBase64);

        GetFingerprintResponse.Entry fallback = new GetFingerprintResponse.Entry(
                "github.com",
                fingerprintBytes,
                new Date(System.currentTimeMillis() + TimeUnit.DAYS.toMillis(1)),
                signatureBytes);

        CertStoreConfiguration config = TestUtils.getCertStoreConfiguration(
                new Date(),
                new String[]{"github.com"},
                new URL("https://github.com"),
                publicKeyBytes,
                fallback);
        CertStore store = new CertStore(config, cryptoProvider, secureDataStore);
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
        UpdateResult updateResult = store.update(UpdateMode.FORCED);
        assertEquals(UpdateResult.OK, updateResult);

        ValidationResult result = store.validateCertificate(cert);
        assertEquals(ValidationResult.TRUSTED, result);
    }
}
