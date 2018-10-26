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
 * The `SecureDataStore` protocol defines interface for saving to, and loading data
 * from the underlying secure storage. The implementing class should store data as
 * secure as possible. On iOS that typically means that iOS Keychain should be used.
 *
 * @author Tomas Kypta, tomas.kypta@wultra.com
 */
interface SecureDataStore {

    /**
     * Save data to the secure data store.
     *
     * @param data Data to be saved
     * @param key Identifier for the saved data
     * @return True if the data has been properly saved
     */
    fun save(data: ByteArray, key: String): Boolean

    /**
     * Loads data previously stored for given key.
     *
     * @param key Identifier for stored data
     * @return Data object if the store contains previously stored data, null otherwise
     */
    fun load(key: String): ByteArray?

    /**
     * Remove data previously stored for given key.
     *
     * @param key Identifier for the stored data
     */
    fun remove(key: String)
}