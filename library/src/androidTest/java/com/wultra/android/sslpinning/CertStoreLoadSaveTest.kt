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

package com.wultra.android.sslpinning

import android.support.test.runner.AndroidJUnit4
import com.wultra.android.sslpinning.integration.powerauth.PowerAuthCryptoProvider
import com.wultra.android.sslpinning.integration.powerauth.PowerAuthSecureDataStore
import com.wultra.android.sslpinning.model.CachedData
import com.wultra.android.sslpinning.model.CertificateInfo
import org.junit.Assert
import org.junit.Test
import org.junit.runner.RunWith
import java.util.*

/**
 * Test saving and loading of caches.
 *
 * @author Tomas Kypta, tomas.kypta@wultra.com
 */
@RunWith(AndroidJUnit4::class)
class CertStoreLoadSaveTest : CommonTest() {

    @Test
    fun testLoadingPreviouslySavedFingerprints() {
        val config = CertStoreConfiguration.Builder(url, getPublicKeyBytes()).build()
        val store = CertStore(config, PowerAuthCryptoProvider(), PowerAuthSecureDataStore(appContext), remoteDataProvider)

        val cert = getCertificateFromUrl("https://github.com")
        val result = store.validateCertificate(cert)

        // first test no data
        Assert.assertEquals(ValidationResult.EMPTY, result)

        updateAndCheck(store, UpdateMode.FORCED, UpdateResult.OK)

        // test after update
        val result2 = store.validateCertificate(cert)
        Assert.assertEquals(ValidationResult.TRUSTED, result2)

        // create new store that loads saved data
        val store2 = CertStore(config, PowerAuthCryptoProvider(), PowerAuthSecureDataStore(appContext), remoteDataProvider)

        // test with loaded data
        val result3 = store2.validateCertificate(cert)
        Assert.assertEquals(ValidationResult.TRUSTED, result3)
    }

    @Test
    fun testSaveAndLoad() {
        val config = CertStoreConfiguration.Builder(url, getPublicKeyBytes()).build()
        val store = CertStore(config, PowerAuthCryptoProvider(), PowerAuthSecureDataStore(appContext), remoteDataProvider)

        Assert.assertNull(store.loadCachedData())

        val date = Date()
        val nextUpdate = Date(date.time + 10000)
        val certInfos = arrayOf(
                CertificateInfo("github.com", "aaa".toByteArray(), date),
                CertificateInfo("wultra.com", "bbb".toByteArray(), date)
        )
        val data = CachedData(certInfos, nextUpdate)
        store.saveDataToCache(data)

        val loadedData = store.loadCachedData()
        Assert.assertNotNull(loadedData)
        Assert.assertEquals((nextUpdate.time/1000)*1000, loadedData!!.nextUpdate.time)
        Assert.assertEquals(2, loadedData!!.certificates.size)
        val ci = loadedData!!.certificates[0]
        Assert.assertEquals("github.com", ci.commonName)
        Assert.assertEquals("aaa", String(ci.fingerprint))
        Assert.assertEquals((date.time/1000)*1000, ci.expires.time)
    }
}