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

import static com.wultra.android.sslpinning.TestUtilsKt.updateAndCheck;

import android.util.Base64;

import com.wultra.android.sslpinning.integration.DefaultCryptoProvider;
import com.wultra.android.sslpinning.integration.DefaultSecureDataStore;

import org.junit.Before;
import org.junit.Test;

import java.net.URL;
import java.util.UUID;

/**
 * Instrumentation test for update signature validation on a device/emulator.
 * Written in Java to validate Java API compatibility.
 *
 * @author Tomas Kypta, tomas.kypta@wultra.com
 */
public class CertStoreUpdateTestJava extends CommonTest {

    private CertStore[] certStores;

    @Before
    @Override
    public void setUp() {
        super.setUp();
        CertStoreConfiguration config = new CertStoreConfiguration.Builder(getServiceUrl(), getPubKey()).build();
        certStores = new CertStore[]{
                new CertStore(config, new DefaultCryptoProvider(), new DefaultSecureDataStore(getAppContext(), UUID.randomUUID().toString()))
        };
    }

    @Test
    public void testUpdate_ForcedOK() throws Exception {
        for (CertStore store : certStores) {
            updateAndCheck(store, UpdateMode.FORCED, UpdateResult.OK);
        }
    }

    @Test
    public void testUpdate_RemoteDirect() throws Exception {
        for (CertStore store : certStores) {
            updateAndCheck(store, UpdateMode.FORCED, UpdateResult.OK, UpdateType.DIRECT);
        }
    }

    @Test
    public void testUpdate_DefaultMode() throws Exception {
        for (CertStore store : certStores) {
            updateAndCheck(store, UpdateMode.DEFAULT, UpdateResult.OK, UpdateType.DIRECT);
            updateAndCheck(store, UpdateMode.DEFAULT, UpdateResult.OK, UpdateType.NO_UPDATE);
        }
    }

    @Test
    public void testUpdate_InvalidSignature() throws Exception {
        String badKey = "BEG6g28LNWRcmdFzexSNTKPBYZnDtKrCyiExFKbktttfKAF7wG4Cx1Nycr5PwCoICG1dRseLyuDxUilAmppPxAo=";
        byte[] badKeyBytes = Base64.decode(badKey, Base64.NO_WRAP);
        CertStoreConfiguration config = new CertStoreConfiguration.Builder(getServiceUrl(), badKeyBytes).build();
        CertStore[] badStores = {
                new CertStore(config, new DefaultCryptoProvider(), new DefaultSecureDataStore(getAppContext(), UUID.randomUUID().toString()))
        };
        for (CertStore store : badStores) {
            updateAndCheck(store, UpdateMode.FORCED, UpdateResult.INVALID_SIGNATURE);
        }
    }

    @Test
    public void testUpdate_NetworkError() throws Exception {
        URL badUrl = new URL("https://localhost:1/non-existent");
        CertStoreConfiguration config = new CertStoreConfiguration.Builder(badUrl, getPubKey()).build();
        CertStore[] badStores = {
                new CertStore(config, new DefaultCryptoProvider(), new DefaultSecureDataStore(getAppContext(), UUID.randomUUID().toString()))
        };
        for (CertStore store : badStores) {
            updateAndCheck(store, UpdateMode.FORCED, UpdateResult.NETWORK_ERROR);
        }
    }
}
