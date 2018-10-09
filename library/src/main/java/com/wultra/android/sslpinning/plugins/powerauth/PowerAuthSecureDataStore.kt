package com.wultra.android.sslpinning.plugins.powerauth

import android.content.Context
import com.wultra.android.sslpinning.interfaces.SecureDataStore
import io.getlime.security.powerauth.keychain.PA2Keychain

/**
 * The [PowerAuthSecureDataStore] implements [SecureDataStore] interface with using
 * [PA2Keychain] as underlying data storage.
 * To initialize the data store, you have to provide keychain identifier.
 *
 * @author Tomas Kypta, tomas.kypta@wultra.com
 */
class PowerAuthSecureDataStore(private val context: Context,
                               keychainIdentifier: String = PowerAuthSecureDataStore.defaultKeychainIdentifier) : SecureDataStore {

    companion object {
        @JvmStatic
        val defaultKeychainIdentifier = "com.wultra.WultraCertStore"
    }

    private val keychain: PA2Keychain

    init {
        keychain = PA2Keychain(keychainIdentifier)
    }


    override fun save(data: ByteArray, key: String): Boolean {
        keychain.putDataForKey(context, data, key)
        return true
    }

    override fun load(key: String): ByteArray? {
        return keychain.dataForKey(context, key)
    }

    override fun remove(key: String) {
        keychain.removeDataForKey(context, key)
    }
}

