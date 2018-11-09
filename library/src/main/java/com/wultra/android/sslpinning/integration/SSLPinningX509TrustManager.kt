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

package com.wultra.android.sslpinning.integration

import com.wultra.android.sslpinning.CertStore
import com.wultra.android.sslpinning.ValidationResult
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import javax.net.ssl.X509TrustManager

/**
 * Trust manager for validating server certificates with WultraSSLPinning.
 *
 * @author Tomas Kypta, tomas.kypta@wultra.com
 */
class SSLPinningX509TrustManager(private val certStore: CertStore) : X509TrustManager {

    override fun checkClientTrusted(chain: Array<out X509Certificate>, authType: String) {
    }

    override fun checkServerTrusted(chain: Array<out X509Certificate>, authType: String) {
        if (certStore.validateCertificate(chain[0]) != ValidationResult.TRUSTED) {
            // reject
            throw CertificateException("WultraSSLpinning doesn't trust the server certificate")
        }
    }

    override fun getAcceptedIssuers(): Array<X509Certificate> {
        return arrayOf()
    }
}