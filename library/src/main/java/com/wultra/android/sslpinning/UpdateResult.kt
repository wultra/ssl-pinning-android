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

/**
 * Result of update request.
 *
 * @author Tomas Kypta, tomas.kypta@wultra.com
 */
enum class UpdateResult {
    /**
     * Update succeeded. Everything is ok.
     */
    OK,
    /**
     * Update is scheduled and will be perfomed in background.
     */
    SCHEDULED,
    /**
     * [CertStore] is empty. There's no valid certificate fingeprint to validate server cert against.
     * Might happen when all the certificate fingerprints are already expired.
     */
    STORE_IS_EMPTY,
    /**
     * There was an error in network communication with the server.
     */
    NETWORK_ERROR,
    /**
     * The update request returned invalid data from the server.
     */
    INVALID_DATA,
    /**
     * The update request returned data which did not pass the signature validation.
     */
    INVALID_SIGNATURE
}