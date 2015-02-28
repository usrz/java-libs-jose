package org.usrz.jose;

import org.testng.annotations.Test;
import org.usrz.jose.jwe.JWEHeader;
import org.usrz.jose.jwk.ec.ECPrivateJWK;
import org.usrz.jose.jwk.ec.ECPublicJWK;
import org.usrz.jose.jwk.oct.OctetSequenceJWK;
import org.usrz.jose.jws.JWSHeader;
import org.usrz.libs.testing.AbstractTest;

public class BuildersTest extends AbstractTest {

    @Test
    public void testJWEHeaderBuilder() {
        final JWEHeader o = new JWEHeader.Builder().build();
        assertTrue(o instanceof JWEHeader);
        assertNotNull(o);
    }

    @Test
    public void testJWSHeaderBuilder() {
        final JWSHeader o = new JWSHeader.Builder().build();
        assertTrue(o instanceof JWSHeader);
        assertNotNull(o);
    }

    @Test
    public void testECPrivateJWKBuilder() {
        final ECPrivateJWK o = new ECPrivateJWK.Builder().build();
        assertTrue(o instanceof ECPrivateJWK);
        assertNotNull(o);
    }

    @Test
    public void testECPublicJWKBuilder() {
        final ECPublicJWK o = new ECPublicJWK.Builder().build();
        assertTrue(o instanceof ECPublicJWK);
        assertNotNull(o);
    }

    @Test
    public void testOctetSequenceJWKBuilder() {
        final OctetSequenceJWK o = new OctetSequenceJWK.Builder().build();
        assertTrue(o instanceof OctetSequenceJWK);
        assertNotNull(o);
    }

}
