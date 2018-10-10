package com.wultra.android.sslpinning.util

import java.security.cert.X509Certificate

/**
 * @author Tomas Kypta, tomas.kypta@wultra.com
 */
class CertUtils {

    companion object {
        fun parseCommonName(certificate: X509Certificate): String {
            val dnParser = DistinguishedNameParser(certificate.subjectX500Principal)
            return dnParser.findMostSpecific("CN")
        }
    }
}