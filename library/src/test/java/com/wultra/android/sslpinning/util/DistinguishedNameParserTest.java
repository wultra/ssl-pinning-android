package com.wultra.android.sslpinning.util;

import org.junit.Assert;
import org.junit.Test;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import javax.net.ssl.HttpsURLConnection;
import javax.security.auth.x500.X500Principal;

/**
 * @author Tomas Kypta, tomas.kypta@wultra.com
 */
public class DistinguishedNameParserTest {

    @Test
    public void testGithubCN() throws Exception {
        testCNForURL("github.com", "https://github.com");
    }

    @Test
    public void testGoogleCN() throws Exception {
        testCNForURL("www.google.com", "https://www.google.com");
    }

    private void testCNForURL(String expectedCN, String urlString) throws IOException {
        X509Certificate cert = getCertificate(urlString);
        X500Principal principal = cert.getSubjectX500Principal();
        String cn = new DistinguishedNameParser(principal).findMostSpecific("CN");
        Assert.assertEquals(expectedCN,  cn);
    }

    static X509Certificate getCertificate(String urlString) throws IOException {
        URL url = new URL(urlString);
        HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
        try {
            connection.connect();
            Certificate[] certificates = connection.getServerCertificates();
            return (X509Certificate) certificates[0];
        } finally {
            connection.disconnect();
        }
    }
}
