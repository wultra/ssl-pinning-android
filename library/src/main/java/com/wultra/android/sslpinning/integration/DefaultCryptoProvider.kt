/*
 * Copyright (c) 2025, Wultra s.r.o. (www.wultra.com).
 *
 * All rights reserved. This source code can be used only for purposes specified
 * by the given license contract signed by the rightful deputy of Wultra s.r.o.
 * This source code can be used only by the owner of the license.
 *
 * Any disputes arising in respect of this agreement (license) shall be brought
 * before the Municipal Court of Prague.
 */

package com.wultra.android.sslpinning.integration

import com.wultra.android.sslpinning.interfaces.CryptoProvider
import com.wultra.android.sslpinning.interfaces.ECPublicKey
import com.wultra.android.sslpinning.interfaces.SignedData
import com.wultra.android.sslpinning.service.WultraDebug
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.PublicKey
import java.security.SecureRandom
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.security.spec.X509EncodedKeySpec

class DefaultCryptoProvider: CryptoProvider {

    private val randomGenerator = SecureRandom()

    override fun ecdsaValidateSignature(signedData: SignedData, publicKey: ECPublicKey): Boolean {
        val exKey = publicKey as? DefaultProviderPublicKey ?: throw IllegalArgumentException("Invalid ECPublicKey object.")
        return try {
            val signature = Signature.getInstance("SHA256withECDSA")
            signature.initVerify(exKey.publicKey)
            signature.update(signedData.data)
            signature.verify(signedData.signature)
        } catch (e: Exception) {
            e.printStackTrace()
            false
        }
    }

    override fun importECPublicKey(publicKey: ByteArray): ECPublicKey? {
        return try {
            val x509key = convertX963ToX509(publicKey) // we expect X9.63 key
            val keyFactory = KeyFactory.getInstance("EC")
            val publicKeySpec = X509EncodedKeySpec(x509key)
            DefaultProviderPublicKey(keyFactory.generatePublic(publicKeySpec))
        } catch (e: Exception) {
            WultraDebug.error("Failed to import EC public key: $e")
            null
        }
    }

    @Throws
    fun convertX963ToX509(x963Key: ByteArray, curveName: String = "secp256r1"): ByteArray {

        require(x963Key.isNotEmpty() && x963Key[0] == 0x04.toByte()) { "Invalid X9.63 key format" }

        val keySize = (x963Key.size - 1) / 2
        val x = BigInteger(1, x963Key.copyOfRange(1, 1 + keySize))
        val y = BigInteger(1, x963Key.copyOfRange(1 + keySize, x963Key.size))

        // Load EC curve parameters
        val params = AlgorithmParameters.getInstance("EC").apply {
            init(ECGenParameterSpec(curveName))
        }
        val ecSpec = params.getParameterSpec(ECParameterSpec::class.java)

        // Create EC public key from X and Y coordinates
        val ecPoint = ECPoint(x, y)
        val publicKeySpec = ECPublicKeySpec(ecPoint, ecSpec)
        val keyFactory = KeyFactory.getInstance("EC")
        val publicKey = keyFactory.generatePublic(publicKeySpec)

        return publicKey.encoded // X.509 SPKI format
    }

    override fun hashSha256(data: ByteArray): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        return digest.digest(data)
    }

    override fun getRandomData(length: Int): ByteArray {
        val bytes = ByteArray(length)
        randomGenerator.nextBytes(bytes)
        return bytes
    }
}

private data class DefaultProviderPublicKey(val publicKey: PublicKey) : ECPublicKey
