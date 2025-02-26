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

import com.wultra.android.sslpinning.CertStore
import com.wultra.android.sslpinning.integration.SSLPinningIntegration
import com.wultra.android.sslpinning.integration.SSLPinningX509TrustManager
import io.getlime.security.powerauth.networking.ssl.HttpClientValidationStrategy
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.X509TrustManager

/**
 * Validation strategy for PowerAuth SDK incorporating WultraSSLPinning.
 *
 * It adds extra [X509TrustManager] to the SSLContext in front of the default trust managers.
 * This way first WultraSSLPinning is checked. Then the standard certificate validation
 * has its way.
 *
 * @property certStore Instance of [CertStore] based on PowerAuthSDK.
 */
class PowerAuthSslPinningValidationStrategy(private val certStore: CertStore) : HttpClientValidationStrategy {

    /**
     * Trust manager for validating server certificates with WultraSSLPinning.
     */
    private val sslPinningTrustManager = SSLPinningX509TrustManager(certStore)

    override fun getHostnameVerifier(): HostnameVerifier? {
        return null
    }

    override fun getSSLSocketFactory(): SSLSocketFactory? {
        return SSLPinningIntegration.createSSLPinningSocketFactory(sslPinningTrustManager)
    }
}