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
import com.wultra.android.sslpinning.integration.DefaultCryptoProvider
import com.wultra.android.sslpinning.interfaces.*
import io.mockk.MockKAnnotations
import io.mockk.every
import io.mockk.impl.annotations.MockK
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.After
import org.junit.Before
import org.junit.BeforeClass
import java.security.MessageDigest
import java.security.Security

/**
 * Common setup for Kotlin-based tests.
 *
 * @author Tomas Kypta, tomas.kypta@wultra.com
 */
open class CommonKotlinTest {

    val sigHeader = mapOf(CertStore.RESPONSE_SIGNATURE_HEADER to "AAAA")

    @MockK
    lateinit var cryptoProvider: CryptoProvider

    @MockK
    lateinit var secureDataStore: SecureDataStore

    @MockK
    lateinit var handler: Handler

    @MockK
    lateinit var context: Context

    @MockK
    lateinit var sharedPrefs: SharedPreferences

    companion object {

        @BeforeClass
        @JvmStatic
        fun setUpClass() {
            Security.addProvider(BouncyCastleProvider())
        }
    }

    @Before
    fun setUp() {
        MockKAnnotations.init(this, relaxUnitFun = true)

        mockkStatic(Base64::class)
        every { Base64.encodeToString(any(), any()) } answers {
            String(java.util.Base64.getEncoder().encode(it.invocation.args[0] as ByteArray))
        }
        every { Base64.encode(any(), any()) } answers {
            java.util.Base64.getEncoder().encode(it.invocation.args[0] as ByteArray)
        }
        every { Base64.decode(any<String>(), any()) } answers {
            java.util.Base64.getDecoder().decode(it.invocation.args[0] as String)
        }

        mockkStatic(Log::class)
        every { Log.e(any(), any()) } answers {
            println("error: ${it.invocation.args[1] as String}")
            0
        }
        every { Log.w(any(), any<String>()) } answers {
            println("warning: ${it.invocation.args[1] as String}")
            0
        }

        every { cryptoProvider.hashSha256(any()) } answers {
            val digest = MessageDigest.getInstance("SHA-256")
            digest.digest(it.invocation.args[0] as ByteArray)
        }

        every { cryptoProvider.importECPublicKey(any()) } answers {
            DefaultCryptoProvider().importECPublicKey(it.invocation.args[0] as ByteArray)
        }

        every { cryptoProvider.getRandomData(any()) } answers {
            ByteArray(it.invocation.args[0] as Int)
        }

        every { cryptoProvider.ecdsaValidateSignature(any(), any()) } answers {
            val signedData: SignedData = it.invocation.args[0] as SignedData
            val publicKey: ECPublicKey = it.invocation.args[1] as ECPublicKey
            DefaultCryptoProvider().ecdsaValidateSignature(signedData, publicKey)
        }

        every { secureDataStore.load(any()) } returns null
        every { secureDataStore.save(any(), any()) } returns false

        mockkStatic(Looper::class)
        every { Looper.getMainLooper() } returns null

        every { handler.post(any()) } answers {
            val runnable = it.invocation.args[0] as Runnable
            runnable.run()
            true
        }

        every { context.applicationContext } returns context
        every { context.getSharedPreferences(any(), any()) } returns sharedPrefs

        every { sharedPrefs.getInt(any(), any()) } returns 0
    }

    @After
    fun tearDown() {
        unmockkAll()
    }
}