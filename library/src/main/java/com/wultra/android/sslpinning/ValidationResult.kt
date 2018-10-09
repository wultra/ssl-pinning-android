package com.wultra.android.sslpinning

/**
 * The result of fingerprint validation.
 *
 * @author Tomas Kypta, tomas.kypta@wultra.com
 */
enum class ValidationResult {

    TRUSTED,
    UNTRUSTED,
    EMPTY
}