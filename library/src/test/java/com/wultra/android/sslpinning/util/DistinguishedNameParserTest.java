package com.wultra.android.sslpinning.util;

import com.wultra.android.sslpinning.TestUtils;

import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;

import java.io.IOException;
import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500Principal;

/**
 * @author Tomas Kypta, tomas.kypta@wultra.com
 */
public class DistinguishedNameParserTest {

    @Ignore
    @Test
    public void testGithubCNFromUrl() throws Exception {
        testCNForURL("github.com", "https://github.com");
    }

    @Ignore
    @Test
    public void testGoogleCNFromUrl() throws Exception {
        testCNForURL("www.google.com", "https://www.google.com");
    }

    @Test
    public void testVariousDN() {
        testCNForDN("github.com",
                "CN=github.com, O=\"GitHub, Inc.\", L=San Francisco, ST=California, C=US, SERIALNUMBER=5157550, OID.1.3.6.1.4.1.311.60.2.1.2=Delaware, OID.1.3.6.1.4.1.311.60.2.1.3=US, OID.2.5.4.15=Private Organization");
        testCNForDN("developer.android.com",
                "CN=developer.android.com, O=Google LLC, L=Mountain View, ST=California, C=US");
        testCNForDN("twitter.com",
                "CN=twitter.com, OU=tsa_o Point of Presence, O=\"Twitter, Inc.\", L=San Francisco, ST=California, C=US");
        testCNForDN("api.twitter.com",
                "CN=api.twitter.com, OU=tsa_o Point of Presence, O=\"Twitter, Inc.\", L=San Francisco, ST=California, C=US");
    }

    private void testCNForURL(String expectedCN, String urlString) throws IOException {
        X509Certificate cert = TestUtils.getCertificateFromUrl(urlString);
        X500Principal principal = cert.getSubjectX500Principal();
        String cn = new DistinguishedNameParser(principal).findMostSpecific("CN");
        Assert.assertEquals(expectedCN,  cn);
    }

    private void testCNForDN(String expectedCN, String providedDN) {
        X500Principal principal = new X500Principal(providedDN);
        String cn = new DistinguishedNameParser(principal).findMostSpecific("CN");
        Assert.assertEquals(expectedCN,  cn);
    }

}
