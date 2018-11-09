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

package com.wultra.android.sslpinning.interfaces


/**
 * The `CryptoProvider` protocol defines interface for performing several
 * cryptographic primitives, required by this library.
 *
 * @author Tomas Kypta, tomas.kypta@wultra.com
 */
interface CryptoProvider {

    /**
     * Validates whether data has not been modified.
     *
     * @param signedData Array of SignedData structures
     * @param publicKey EC public key
     * @return True if all signatures are correct
     */
    fun ecdsaValidateSignatures(signedData: SignedData, publicKey: ECPublicKey): Boolean

    /**
     * Constructs a new ECPublicKey object from given ASN.1 formatted data blob.
     *
     * @param publicKey ASN.1 formatted data blob with EC public ket.
     * @return Object representing public key or nil in case of error.
     */
    fun importECPublicKey(publicKey: ByteArray): ECPublicKey?

    /**
     * Computes SHA-256 hash from given data.
     *
     * @param data Data to be hashed
     * @return 32 bytes hash, calculated as `SHA256(data)`
     */
    fun hashSha256(data: ByteArray): ByteArray
}

/**
 * The `SignedData` structure contains data and signature calculated for the data.
 */
data class SignedData(val data: ByteArray,
                      val signature: ByteArray)

/**
 * The `ECPublicKey` protocol is an abstract interface representing
 * a public key in EC based cryptography.
 */
interface ECPublicKey