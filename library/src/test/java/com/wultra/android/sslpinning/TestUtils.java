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

package com.wultra.android.sslpinning;

import android.os.Handler;

import com.wultra.android.sslpinning.model.GetFingerprintResponse;

import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.lang.reflect.Field;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.HttpsURLConnection;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;


/**
 * @author Tomas Kypta, tomas.kypta@wultra.com
 */
public class TestUtils {
    public static X509Certificate getCertificateFromUrl(String urlString) throws IOException {
        URL url = new URL(urlString);
        HttpURLConnection httpURLConnection = (HttpURLConnection) url.openConnection();
        HttpsURLConnection connection = (HttpsURLConnection) httpURLConnection;
        try {
            connection.connect();
            Certificate[] certificates = connection.getServerCertificates();
            return (X509Certificate) certificates[0];
        } finally {
            connection.disconnect();
        }
    }

    public static CertStoreConfiguration getCertStoreConfiguration(Date expiration, String[] expectedCommonNames, URL serviceUrl, byte[] publicKey, GetFingerprintResponse.Entry fallback) {
        CertStoreConfiguration.Builder builder = new CertStoreConfiguration.Builder(
                serviceUrl, publicKey)
                .identifier(null)
                .expectedCommonNames(expectedCommonNames)
                .fallbackCertificate(fallback);
        return builder.build();
    }

    public static void assignHandler(CertStore certStore, Handler handler) throws Exception {
        Field handlerField = CertStore.class.getDeclaredField("mainThreadHandler");
        handlerField.setAccessible(true);
        handlerField.set(certStore, handler);
    }

    public static UpdateResult updateAndCheck(CertStore store, UpdateMode updateMode, UpdateResult expectedUpdateResult) throws Exception {
        CountDownLatch initLatch = new CountDownLatch(1);
        CountDownLatch latch = new CountDownLatch(1);
        UpdateWrapper updateWrapper = new UpdateWrapper();
        store.update(updateMode, new UpdateObserver() {
            @Override
            public void onUpdateStarted(@NotNull UpdateType type) {
                updateWrapper.setUpdateType(type);
                initLatch.countDown();
            }

            @Override
            public void onUpdateFinished(@NotNull UpdateType type, @NotNull UpdateResult result) {
                updateWrapper.setUpdateResult(result);
                latch.countDown();
            }
        });
        initLatch.await(500, TimeUnit.MILLISECONDS);
        assertNotNull(updateWrapper.getUpdateType());
        if (updateWrapper.getUpdateType().isPerformingUpdate()) {
            assertTrue(latch.await(3, TimeUnit.SECONDS));
        }
        if (expectedUpdateResult != null) {
            assertEquals(expectedUpdateResult, updateWrapper.getUpdateResult());
        }
        return updateWrapper.getUpdateResult();
    }
}
