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
 * The result of fingerprint validation.
 *
 * @author Tomas Kypta, tomas.kypta@wultra.com
 */
enum class ValidationResult {

    /**
     * The challenged server certificate is trusted.
     */
    TRUSTED,
    /**
     * The challenged server certificate is not trusted.
     */
    UNTRUSTED,
    /**
     * The fingerprint database is empty. Or there's no fingerprint for validated common name.
     * Both these situations mean that the store is unable to determine whether the server
     * can be trusted or not.
     *
     * In this case it is recommended to udpate the list of certificate fingerpritns
     * and not to trust the server.
     */
    EMPTY
}