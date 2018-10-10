package com.wultra.android.sslpinning

/**
 * @author Tomas Kypta, tomas.kypta@wultra.com
 */
enum class UpdateResult {
    OK,
    SCHEDULED,
    STORE_IS_EMPTY,
    NETWORK_ERROR,
    INVALID_DATA,
    INVALID_SIGNATURE
}