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
 * Defines modes of update request.
 *
 * @author Tomas Kypta, tomas.kypta@wultra.com
 */
enum class UpdateMode {
    /**
     * Default update following periodicity defined in [CertStoreConfiguration].
     */
    DEFAULT,

    /**
     * Forced update performed immediately.
     * Use only if a "validate*" method returns [ValidationResult.EMPTY].
     * Otherwise [DEFAULT] value is recommended.
     *
     * Note that this value causes synchronous (blocking) update request.
     */
    FORCED
}