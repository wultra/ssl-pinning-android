package com.wultra.android.sslpinning.util

import com.google.gson.Gson
import com.google.gson.GsonBuilder

/**
 * @author Tomas Kypta, tomas.kypta@wultra.com
 */
internal class CertStoreUtils {

    companion object {
        val gson: Gson = GsonBuilder()
                    .registerTypeAdapter(ByteArray::class.java, ByteArrayTypeAdapter::class.java)
                    .create()
    }
}