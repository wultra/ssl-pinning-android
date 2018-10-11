package com.wultra.android.sslpinning.plugins.powerauth

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