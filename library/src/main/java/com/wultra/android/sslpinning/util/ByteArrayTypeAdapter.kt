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