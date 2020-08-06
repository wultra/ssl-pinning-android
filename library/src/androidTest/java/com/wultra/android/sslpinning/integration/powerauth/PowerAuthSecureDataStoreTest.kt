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

package com.wultra.android.sslpinning.integration.powerauth

import android.support.test.InstrumentationRegistry
import android.support.test.runner.AndroidJUnit4
import org.junit.Test

import org.junit.Assert.*
import org.junit.Before
import org.junit.runner.RunWith

/**
 * Test [PowerAuthSecureDataStore] methods.
 */
@RunWith(AndroidJUnit4::class)
class PowerAuthSecureDataStoreTest {

    val appContext = InstrumentationRegistry.getTargetContext()

    lateinit var paSecureDataStore: PowerAuthSecureDataStore

    companion object {
        private const val key = "a-key"
    }
    @Before
    fun setUp() {
        paSecureDataStore = PowerAuthSecureDataStore(appContext)
        paSecureDataStore.remove(key)
    }

    @Test
    fun saveAndLoad() {
        val loadedBoforeSave = paSecureDataStore.load(key)
        assertNull(loadedBoforeSave)

        val data = "hello".toByteArray()
        paSecureDataStore.save(data, key)

        val loadedData = paSecureDataStore.load(key)
        assertArrayEquals(data, loadedData)

        val data2 = "world".toByteArray()
        paSecureDataStore.save(data2, key)

        val loadedData2 = paSecureDataStore.load(key)
        assertArrayEquals(data2, loadedData2)
    }

    @Test
    fun remove() {
        val key = "a-key"
        paSecureDataStore.remove(key)
        val loaded = paSecureDataStore.load(key)
        assertNull(loaded)

        val data = "lorem ipsum".toByteArray()
        paSecureDataStore.save(data, key)
        val loadedAfterSave = paSecureDataStore.load(key)
        assertArrayEquals(data, loadedAfterSave)

        paSecureDataStore.remove(key)
        val loadedAfterRemoval = paSecureDataStore.load(key)
        assertNull(loadedAfterRemoval)
    }
}