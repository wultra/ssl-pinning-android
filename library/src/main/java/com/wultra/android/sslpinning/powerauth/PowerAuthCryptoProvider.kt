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

package com.wultra.android.sslpinning.powerauth

import com.wultra.android.sslpinning.interfaces.CryptoProvider
import com.wultra.android.sslpinning.interfaces.ECPublicKey
import com.wultra.android.sslpinning.interfaces.SignedData
import io.getlime.security.powerauth.core.CryptoUtils
import java.lang.IllegalArgumentException

/**
 * @author Tomas Kypta, tomas.kypta@wultra.com
 */
class PowerAuthCryptoProvider : CryptoProvider {

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
}


data class PA2ECPublicKey(val data: ByteArray) : ECPublicKey