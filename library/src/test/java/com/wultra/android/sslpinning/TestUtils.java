package com.wultra.android.sslpinning;

import com.wultra.android.sslpinning.model.GetFingerprintResponse;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.net.ssl.HttpsURLConnection;


/**
 * @author Tomas Kypta, tomas.kypta@wultra.com
 */
public class TestUtils {
    public static X509Certificate getCertificateFromUrl(String urlString) throws IOException {
        URL url = new URL(urlString);
        HttpURLConnection httpURLConnection = (HttpURLConnection) url.openConnection();
        HttpsURLConnection connection = (HttpsURLConnection) httpURLConnection;
        try {
            connection.connect();
            Certificate[] certificates = connection.getServerCertificates();
            return (X509Certificate) certificates[0];
        } finally {
            connection.disconnect();
        }
    }

    public static CertStoreConfiguration getCertStoreConfiguration(Date expiration, String[] expectedCommonNames, URL serviceUrl, byte[] publicKey, GetFingerprintResponse.Entry fallback) {
        CertStoreConfiguration.Builder builder = new CertStoreConfiguration.Builder(
                serviceUrl, publicKey)
                .identifier(null)
                .expectedCommonNames(expectedCommonNames)
                .fallbackCertificate(fallback);
        return builder.build();
    }
}
