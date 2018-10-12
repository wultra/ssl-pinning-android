package com.wultra.android.sslpinning;

import android.util.Log;

import com.wultra.android.sslpinning.interfaces.CryptoProvider;
import com.wultra.android.sslpinning.interfaces.SecureDataStore;
import com.wultra.android.sslpinning.model.GetFingerprintResponse;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
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
        "javax.security.auth.x500.*"
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

    @Before
    public void setUp() {
        Security.addProvider(new BouncyCastleProvider());

        PowerMockito.mockStatic(android.util.Base64.class);
        when(android.util.Base64.encodeToString(any(byte[].class), anyInt()))
                .thenAnswer(invocation ->
                        new String(java.util.Base64.getEncoder().encode((byte[]) invocation.getArgument(0)))
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
    }

    @Test
    public void testValidationGithub() throws Exception {
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

        byte[] fingerprint = fingerprintBytes;
//        Arrays.fill(fingerprint, (byte)0xff);
        ValidationResult result = store.validateCertificate(cert);
    }
}
