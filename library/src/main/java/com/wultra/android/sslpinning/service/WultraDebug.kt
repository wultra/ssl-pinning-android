package com.wultra.android.sslpinning.service

import android.util.Log

/**
 * @author Tomas Kypta, tomas.kypta@wultra.com
 */
internal class WultraDebug {

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

        var loggingLevel = WultraLoggingLevel.RELEASE

        fun info(message: String) {
            if (loggingLevel == WultraLoggingLevel.DEBUG) {
                Log.d(LOG_TAG, message)
            }
        }

        fun warning(message: String) {
            if (loggingLevel != WultraLoggingLevel.NONE) {
                Log.w(LOG_TAG, message)
            }
        }

        fun error(message: String) {
            if (loggingLevel != WultraLoggingLevel.NONE) {
                Log.e(LOG_TAG, message)
            }
        }
    }
}