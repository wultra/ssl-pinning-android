package com.wultra.android.sslpinning.util

import android.util.Base64
import com.google.gson.*
import java.lang.reflect.Type

/**
 * @author Tomas Kypta, tomas.kypta@wultra.com
 */
class ByteArrayTypeAdapter : JsonSerializer<ByteArray>, JsonDeserializer<ByteArray> {

    override fun serialize(src: ByteArray, typeOfSrc: Type, context: JsonSerializationContext?): JsonElement {
        return JsonPrimitive(Base64.encodeToString(src, Base64.NO_WRAP))
    }

    override fun deserialize(json: JsonElement, typeOfT: Type, context: JsonDeserializationContext?): ByteArray {
        return Base64.decode(json.asString, Base64.NO_WRAP)
    }
}