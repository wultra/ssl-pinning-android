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
import android.content.SharedPreferences;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;

import com.wultra.android.sslpinning.integration.powerauth.PA2ECPublicKey;
import com.wultra.android.sslpinning.interfaces.CryptoProvider;
import com.wultra.android.sslpinning.interfaces.ECPublicKey;
import com.wultra.android.sslpinning.interfaces.SecureDataStore;
import com.wultra.android.sslpinning.interfaces.SignedData;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.BeforeClass;
import org.mockito.Mock;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;

import java.security.MessageDigest;
import java.security.Security;
import java.util.Base64;

import io.getlime.security.powerauth.crypto.lib.util.KeyConvertor;
import io.getlime.security.powerauth.crypto.lib.util.SignatureUtils;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

/**
 * Common setup for java-based tests.
 *
 * @author Tomas Kypta, tomas.kypta@wultra.com
 */
@PowerMockIgnore({
        "javax.net.ssl.*",
        "javax.security.auth.x500.*",
        "org.bouncycastle.*",
        "java.security.*"
})
@PrepareForTest({
        android.util.Base64.class,
        Log.class,
        Looper.class
})
public abstract class CommonJavaTest {

    @Mock
    protected Context context;

    @Mock
    protected SharedPreferences sharedPrefs;

    @Mock
    protected CryptoProvider cryptoProvider;

    @Mock
    protected SecureDataStore secureDataStore;

    @Mock
    protected Handler handler;

    @BeforeClass
    public static void setUpClass() {
        Security.addProvider(new BouncyCastleProvider());
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
                        Base64.getDecoder().decode((String) invocation.getArgument(0))
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
                    final KeyConvertor keyConvertor = new KeyConvertor();
                    return utils.validateECDSASignature(signedData.getData(),
                            signedData.getSignature(),
                            keyConvertor.convertBytesToPublicKey(pubKey.getData()));
                });

        PowerMockito.mockStatic(Looper.class);
        when(Looper.getMainLooper())
                .thenReturn(null);

        when(handler.post(any()))
                .thenAnswer(invocation -> {
                    Runnable runnable = invocation.getArgument(0);
                    Thread t = new Thread(runnable);
                    t.start();
                    return true;
                });

        when(context.getApplicationContext())
                .thenReturn(context);
        when(context.getSharedPreferences(anyString(), anyInt()))
                .thenReturn(sharedPrefs);
    }
}
