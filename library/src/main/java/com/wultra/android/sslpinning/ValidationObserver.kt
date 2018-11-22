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
 * Observer for validation failures.
 *
 * When registered receives all validation failures happending on the given [CertStore].
 * Callbacks are executed on the main thread.
 *
 * @author Tomas Kypta, tomas.kypta@wultra.com
 *
 * @since 0.9.0
 */
interface ValidationObserver {

    /**
     * Called when a validation for a common name is deemed [ValidationResult.UNTRUSTED].
     *
     * @param commonName The common name that was validated with result [ValidationResult.UNTRUSTED].
     */
    fun onValidationUntrusted(commonName: String)

    /**
     * Called when a validation for a common name is deemed [ValidationResult.EMPTY].
     *
     * @param commonName The common name that was validated with result [ValidationResult.EMPTY].
     */
    fun onValidationEmpty(commonName: String)
}