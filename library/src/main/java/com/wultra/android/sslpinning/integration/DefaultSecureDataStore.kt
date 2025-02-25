/*
 * Copyright (c) 2024, Wultra s.r.o. (www.wultra.com).
 *
 * All rights reserved. This source code can be used only for purposes specified
 * by the given license contract signed by the rightful deputy of Wultra s.r.o.
 * This source code can be used only by the owner of the license.
 *
 * Any disputes arising in respect of this agreement (license) shall be brought
 * before the Municipal Court of Prague.
 */

package com.wultra.android.sslpinning.integration

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKeys
import com.wultra.android.sslpinning.interfaces.SecureDataStore

class DefaultSecureDataStore @JvmOverloads constructor(
    appContext: Context,
    identifier: String = defaultIdentifier
): SecureDataStore {

    companion object {
        @JvmStatic
        val defaultIdentifier = "com.wultra.DefaultWultraCertStore"
    }

    private val preferences = EncryptedSharedPreferences.create(
        identifier,
        MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC),
        appContext,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )

    override fun save(data: ByteArray, key: String): Boolean {
        preferences.edit().putString(key, String(data, Charsets.ISO_8859_1)).apply()
        return true
    }

    override fun load(key: String): ByteArray? {
        return preferences.getString(key, null)?.toByteArray(Charsets.ISO_8859_1)
    }

    override fun remove(key: String) {
        preferences.edit().remove(key).apply()
    }
}