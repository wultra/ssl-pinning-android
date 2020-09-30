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

package com.wultra.android.sslpinning.integration.powerauth

import com.wultra.android.sslpinning.interfaces.CryptoProvider
import com.wultra.android.sslpinning.interfaces.ECPublicKey
import com.wultra.android.sslpinning.interfaces.SignedData
import io.getlime.security.powerauth.core.CryptoUtils
import java.lang.IllegalArgumentException
import java.security.SecureRandom

/**
 * Implementation of [CryptoProvider] using crypto function provided by PowerAuthSDK.
 * If your app is already using PowerAuth, this is the recommended implementation for you.
 *
 * @author Tomas Kypta, tomas.kypta@wultra.com
 */
class PowerAuthCryptoProvider : CryptoProvider {

    private val randomGenerator = SecureRandom()

    override fun ecdsaValidateSignatures(signedData: SignedData, publicKey: ECPublicKey): Boolean {
        val ecKey = publicKey as? PA2ECPublicKey ?: throw IllegalArgumentException("Invalid ECPublicKey object.")

        return CryptoUtils.ecdsaValidateSignature(signedData.data, signedData.signature, ecKey.data)
    }

    override fun importECPublicKey(publicKey: ByteArray): ECPublicKey? {
        // TODO consider validation of the data
        return PA2ECPublicKey(data = publicKey)
    }

    override fun hashSha256(data: ByteArray): ByteArray {
        return CryptoUtils.hashSha256(data)
    }

    override fun getRandomData(length: Int): ByteArray {
        val bytes = ByteArray(length)
        randomGenerator.nextBytes(bytes)
        return bytes
    }
}

/**
 * An implementation `ECPublicKey` protocol of a public key in EC based cryptography
 * done with PowerAuth.
 */
data class PA2ECPublicKey(val data: ByteArray) : ECPublicKey