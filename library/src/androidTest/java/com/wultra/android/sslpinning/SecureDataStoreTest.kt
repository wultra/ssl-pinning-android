/*
 * Copyright 2020 Wultra s.r.o.
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

package com.wultra.android.sslpinning

import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.wultra.android.sslpinning.integration.DefaultSecureDataStore
import com.wultra.android.sslpinning.interfaces.SecureDataStore
import org.junit.Test

import org.junit.Assert.*
import org.junit.Before
import org.junit.runner.RunWith
import java.util.UUID

/**
 * Test the default secure storage implementation methods.
 */
@RunWith(AndroidJUnit4::class)
class SecureDataStoreTest {

    val appContext = InstrumentationRegistry.getInstrumentation().targetContext

    lateinit var dataStores: Array<SecureDataStore>

    companion object {
        private const val key = "a-key"
    }
    @Before
    fun setUp() {
        dataStores = arrayOf(
            DefaultSecureDataStore(appContext, UUID.randomUUID().toString())
        )
        dataStores.forEach { it.remove(key) }
    }

    @Test
    fun saveAndLoad() {
        dataStores.forEach { store ->
            val loadedBoforeSave = store.load(key)
            assertNull(loadedBoforeSave)

            val data = "hello".toByteArray()
            store.save(data, key)

            val loadedData = store.load(key)
            assertArrayEquals(data, loadedData)

            val data2 = "world".toByteArray()
            store.save(data2, key)

            val loadedData2 = store.load(key)
            assertArrayEquals(data2, loadedData2)
        }
    }

    @Test
    fun remove() {
        dataStores.forEach { store ->
            val key = "a-key"
            store.remove(key)
            val loaded = store.load(key)
            assertNull(loaded)

            val data = "lorem ipsum".toByteArray()
            store.save(data, key)
            val loadedAfterSave = store.load(key)
            assertArrayEquals(data, loadedAfterSave)

            store.remove(key)
            val loadedAfterRemoval = store.load(key)
            assertNull(loadedAfterRemoval)
        }
    }
}