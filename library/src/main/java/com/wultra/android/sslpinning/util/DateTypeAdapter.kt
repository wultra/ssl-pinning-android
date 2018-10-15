package com.wultra.android.sslpinning.util

import com.google.gson.JsonDeserializationContext
import com.google.gson.JsonDeserializer
import com.google.gson.JsonElement
import java.lang.reflect.Type
import java.util.*

/**
 * Type adapter for parsing [Date] from update json.
 *
 * @author Tomas Kypta, tomas.kypta@wultra.com
 */
class DateTypeAdapter : JsonDeserializer<Date> {

    override fun deserialize(json: JsonElement, typeOfT: Type, context: JsonDeserializationContext?): Date {
        return Date(json.asLong * 1000)
    }
}