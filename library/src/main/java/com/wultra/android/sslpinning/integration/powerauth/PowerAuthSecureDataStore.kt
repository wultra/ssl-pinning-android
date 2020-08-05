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

import android.content.Context
import com.wultra.android.sslpinning.interfaces.SecureDataStore
import io.getlime.security.powerauth.keychain.Keychain
import io.getlime.security.powerauth.keychain.KeychainFactory
import io.getlime.security.powerauth.keychain.KeychainProtection

/**
 * The [PowerAuthSecureDataStore] implements [SecureDataStore] interface with using
 * [PA2Keychain] as underlying data storage.
 * To initialize the data store, you have to provide keychain identifier.
 *
 * @property contains Application context
 * @param keychainIdentifier Identifier for the data store. Used to distinguish multiple instances.
 * @param minimumKeychainProtection The minimum level of PowerAuth Keychain content protection.
 *
 * @author Tomas Kypta, tomas.kypta@wultra.com
 */
class PowerAuthSecureDataStore @JvmOverloads constructor(private val context: Context,
                                                         keychainIdentifier: String = defaultKeychainIdentifier,
                                                         minimumKeychainProtection: Int = KeychainProtection.NONE) : SecureDataStore {

    companion object {
        @JvmStatic
        val defaultKeychainIdentifier = "com.wultra.WultraCertStore"
    }

    private val keychain: Keychain = KeychainFactory.getKeychain(context, keychainIdentifier, minimumKeychainProtection)


    override fun save(data: ByteArray, key: String): Boolean {
        keychain.putData(data, key)
        return true
    }

    override fun load(key: String): ByteArray? {
        return keychain.getData(key)
    }

    override fun remove(key: String) {
        keychain.remove(key)
    }
}

