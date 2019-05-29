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

package com.wultra.android.sslpinning.service

import android.util.Log

/**
 * Simple logging abstraction for the library.
 *
 * @author Tomas Kypta, tomas.kypta@wultra.com
 */
class WultraDebug {

    /**
     * List of logging levels for [WultraDebug].
     */
    enum class WultraLoggingLevel {
        /**
         * Log all log including debug logs.
         *
         * Don't use on release builds.
         */
        DEBUG,

        /**
         * Log only logs suitable for release (warning and error).
         */
        RELEASE,

        /**
         * Don't log anything.
         */
        NONE
    }

    companion object {
        const val LOG_TAG = "Wultra-SSL-Pinning"

        /**
         * Current logging level.
         */
        var loggingLevel = WultraLoggingLevel.RELEASE

        /**
         * Log info level message.
         */
        fun info(message: String) {
            if (loggingLevel == WultraLoggingLevel.DEBUG) {
                Log.i(LOG_TAG, message)
            }
        }

        /**
         * Log warning level message.
         */
        fun warning(message: String) {
            if (loggingLevel != WultraLoggingLevel.NONE) {
                Log.w(LOG_TAG, message)
            }
        }

        /**
         * Log error level message.
         */
        fun error(message: String) {
            if (loggingLevel != WultraLoggingLevel.NONE) {
                Log.e(LOG_TAG, message)
            }
        }
    }
}