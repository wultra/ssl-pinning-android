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

import java.security.cert.X509Certificate

/**
 * Utility methods for handling certificates.
 *
 * @author Tomas Kypta, tomas.kypta@wultra.com
 */
class CertUtils {

    companion object {

        /**
         * Parse common name (CN) out of certificate's distinguished name (DN).
         *
         * Note: on Android there's no native API for parsing it.
         * And we don't want to include Spongy Castle (https://rtyley.github.io/spongycastle)
         * for this task.
         * The parsing is taken from OkHttp library [DistinguishedNameParser].
         */
        fun parseCommonName(certificate: X509Certificate): String {
            val dnParser = DistinguishedNameParser(certificate.subjectX500Principal)
            return dnParser.findMostSpecific("CN")
        }
    }
}