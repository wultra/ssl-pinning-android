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
import com.wultra.android.sslpinning.CertStore
import com.wultra.android.sslpinning.CertStoreConfiguration

/**
 * Creates a new instance of [CertStore] preconfigured with
 * [com.wultra.android.sslpinning.interfaces.CryptoProvider]
 * and [com.wultra.android.sslpinning.interfaces.SecureDataStore]
 * implemented on top of PowerAuthSDK.
 *
 * @param configuration Configuration for [CertStore]
 * @param context Application context
 * @param keychainIdentifier Identifier for the data store. Used to distinguish multiple instances.
 * @return New instance of [CertStore].
 *
 * @author Tomas Kypta, tomas.kypta@wultra.com
 */
fun CertStore.Companion.powerAuthCertStore(configuration: CertStoreConfiguration,
                                           context: Context,
                                           keychainIdentifier: String? = null): CertStore {
    val secureDataStore = if (keychainIdentifier == null) {
        PowerAuthSecureDataStore(context)
    } else {
        PowerAuthSecureDataStore(context, keychainIdentifier)
    }
    return CertStore(configuration = configuration,
            cryptoProvider = PowerAuthCryptoProvider(),
            secureDataStore = secureDataStore)
}

/**
 * Compatibility API mainly for usage from Java.
 *
 * Allows calling `CertStore.powerAuthCertStore()` with `PowerAuthCertStore.createInstance()`.
 */
class PowerAuthCertStore {
    companion object {

        /**
         * Creates a new instance of [CertStore] preconfigured with
         * [com.wultra.android.sslpinning.interfaces.CryptoProvider]
         * and [com.wultra.android.sslpinning.interfaces.SecureDataStore]
         * implemented on top of PowerAuthSDK.
         *
         * @param configuration Configuration for [CertStore]
         * @param context Application context
         * @param keychainIdentifier Identifier for the data store. Used to distinguish multiple instances.
         * @return New instance of [CertStore].
         */
        @JvmStatic
        @JvmOverloads
        fun createInstance(configuration: CertStoreConfiguration,
                           context: Context,
                           keychainIdentifier: String? = null): CertStore {
            return CertStore.powerAuthCertStore(configuration, context, keychainIdentifier)
        }
    }
}