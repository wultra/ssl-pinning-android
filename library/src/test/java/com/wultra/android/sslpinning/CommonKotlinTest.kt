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

package com.wultra.android.sslpinning

import android.content.Context
import android.content.SharedPreferences
import android.os.Handler
import android.os.Looper
import android.util.Base64
import android.util.Log
import com.wultra.android.sslpinning.integration.powerauth.PA2ECPublicKey
import com.wultra.android.sslpinning.interfaces.CryptoProvider
import com.wultra.android.sslpinning.interfaces.ECPublicKey
import com.wultra.android.sslpinning.interfaces.SecureDataStore
import com.wultra.android.sslpinning.interfaces.SignedData
import io.getlime.security.powerauth.crypto.lib.config.PowerAuthConfiguration
import io.getlime.security.powerauth.crypto.lib.util.SignatureUtils
import io.getlime.security.powerauth.provider.CryptoProviderUtilBouncyCastle
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.Before
import org.junit.BeforeClass
import org.mockito.ArgumentMatchers
import org.mockito.ArgumentMatchers.anyString
import org.mockito.Mock
import org.mockito.Mockito
import org.mockito.Mockito.`when`
import org.mockito.Mockito.anyInt
import org.powermock.api.mockito.PowerMockito
import org.powermock.core.classloader.annotations.PowerMockIgnore
import org.powermock.core.classloader.annotations.PrepareForTest
import java.security.MessageDigest
import java.security.Security

/**
 * Common setup for Kotlin-based tests.
 *
 * @author Tomas Kypta, tomas.kypta@wultra.com
 */
@PowerMockIgnore("javax.net.ssl.*", "javax.security.auth.x500.*", "org.bouncycastle.*", "java.security.*")
@PrepareForTest(Base64::class,
        Log::class,
        Looper::class)
open class CommonKotlinTest {

    @Mock
    lateinit var cryptoProvider: CryptoProvider

    @Mock
    lateinit var secureDataStore: SecureDataStore

    @Mock
    lateinit var handler: Handler

    @Mock
    lateinit var context: Context

    @Mock
    lateinit var sharedPrefs: SharedPreferences

    companion object {

        @BeforeClass
        @JvmStatic
        fun setUpClass() {
            Security.addProvider(BouncyCastleProvider())
            PowerAuthConfiguration.INSTANCE.keyConvertor = CryptoProviderUtilBouncyCastle()
        }
    }

    fun <T> any(): T = Mockito.any<T>()

    @Before
    fun setUp() {
        PowerMockito.mockStatic(Base64::class.java)
        Mockito.`when`<String>(Base64.encodeToString(any<ByteArray>(), ArgumentMatchers.anyInt()))
                .thenAnswer { invocation -> String(java.util.Base64.getEncoder().encode(invocation.getArgument(0) as ByteArray)) }

        Mockito.`when`<ByteArray>(Base64.encode(any<ByteArray>(), ArgumentMatchers.anyInt()))
                .thenAnswer { invocation -> java.util.Base64.getEncoder().encode(invocation.getArgument(0) as ByteArray) }

        Mockito.`when`<ByteArray>(Base64.decode(ArgumentMatchers.anyString(), ArgumentMatchers.anyInt()))
                .thenAnswer { invocation -> java.util.Base64.getDecoder().decode(invocation.getArgument(0) as String) }

        PowerMockito.mockStatic(Log::class.java)
        Mockito.`when`<Int>(Log.e(ArgumentMatchers.anyString(), ArgumentMatchers.anyString()))
                .then { invocation ->
                    println(invocation.getArgument(1) as String)
                    0
                }

        Mockito.`when`<ByteArray>(cryptoProvider.hashSha256(any()))
                .thenAnswer { invocation ->
                    val digest = MessageDigest.getInstance("SHA-256")
                    digest.digest(invocation.getArgument(0))
                }

        Mockito.`when`<ECPublicKey>(cryptoProvider.importECPublicKey(any()))
                .thenAnswer { invocation -> PA2ECPublicKey(invocation.getArgument(0)) }

        Mockito.`when`<Boolean>(cryptoProvider.ecdsaValidateSignatures(any(), any()))
                .thenAnswer { invocation ->
                    val utils = SignatureUtils()
                    val signedData: SignedData = invocation.getArgument(0)
                    val pubKey: PA2ECPublicKey = invocation.getArgument(1)
                    val keyConvertor = PowerAuthConfiguration.INSTANCE.keyConvertor
                    utils.validateECDSASignature(signedData.data,
                            signedData.signature,
                            keyConvertor.convertBytesToPublicKey(pubKey.data))
                }

        PowerMockito.mockStatic(Looper::class.java)
        Mockito.`when`<Looper>(Looper.getMainLooper())
                .thenReturn(null)

        Mockito.`when`<Boolean>(handler.post(any()))
                .then { invocation ->
                    val runnable = invocation.getArgument<Runnable>(0)
                    runnable.run()
                    return@then true
                }

        `when`(context.applicationContext).thenReturn(context)
        `when`(context.getSharedPreferences(anyString(), anyInt())).thenReturn(sharedPrefs)
    }
}