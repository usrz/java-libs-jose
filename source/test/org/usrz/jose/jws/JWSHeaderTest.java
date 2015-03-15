/* ========================================================================== *
 * Copyright 2014 USRZ.com and Pier Paolo Fumagalli                           *
 * -------------------------------------------------------------------------- *
 * Licensed under the Apache License, Version 2.0 (the "License");            *
 * you may not use this file except in compliance with the License.           *
 * You may obtain a copy of the License at                                    *
 *                                                                            *
 *  http://www.apache.org/licenses/LICENSE-2.0                                *
 *                                                                            *
 * Unless required by applicable law or agreed to in writing, software        *
 * distributed under the License is distributed on an "AS IS" BASIS,          *
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.   *
 * See the License for the specific language governing permissions and        *
 * limitations under the License.                                             *
 * ========================================================================== */
package org.usrz.jose.jws;

import static java.util.Collections.EMPTY_LIST;
import static java.util.Collections.emptyList;
import static java.util.Collections.emptyMap;
import static java.util.Collections.singletonList;
import static java.util.Collections.singletonMap;
import static javax.ws.rs.core.MediaType.TEXT_HTML_TYPE;
import static org.usrz.jose.jws.JWSAlgorithm.ES256;
import static org.usrz.jose.jws.JWSAlgorithm.HS256;
import static org.usrz.jose.jws.JWSAlgorithm.NONE;
import static org.usrz.jose.jws.JWSAlgorithm.PS512;
import static org.usrz.jose.shared.JOSEMediaTypes.APPLICATION_JWS_TYPE;
import static org.usrz.jose.shared.JOSEMediaTypes.APPLICATION_JWT_TYPE;

import java.math.BigInteger;
import java.net.URI;
import java.net.URL;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.testng.annotations.Test;
import org.usrz.jose.AbstractTestParse;
import org.usrz.jose.jwk.JWKKeyType;
import org.usrz.jose.jwk.JWKPublicKeyUse;
import org.usrz.jose.jwk.rsa.RSAPublicJWK;

public class JWSHeaderTest extends AbstractTestParse {

    @Test
    public void testSection3_1_A()
    throws Exception {
        final String json = "{\"typ\":\"JWT\",\"alg\":\"HS256\"}";
        final JWSHeader header = mapper.readValue(json, JWSHeader.class);
        validateObject(json, header);

        assertEquals(header.getAlgorithm(),                       HS256,                "Wrong algorithm");
        assertEquals(header.getMediaType(),                       APPLICATION_JWT_TYPE, "Wrong type");
        assertEquals(header.getContentMediaType(),                null,                 "Wrong contentType");
        assertEquals(header.getKeyId(),                           null,                 "Wrong keyID");
        assertEquals(header.getJsonWebKey(),                      null,                 "Wrong jwk");
        assertEquals(header.getJsonWebKeySetUrl(),                null,                 "Wrong jwkSetURL");
        assertEquals(header.getX509CertificateChain(),            emptyList(),          "Wrong x509CertificateChain");
        assertEquals(header.getX509CertificateThumbprint(),       null,                 "Wrong x509CertificateThumbprint");
        assertEquals(header.getX509CertificateThumbprintSHA256(), null,                 "Wrong x509CertificateThumbprintSHA256");
        assertEquals(header.getX509Url(),                         null,                 "Wrong x509URI");
        assertEquals(header.getCriticalExtensions(),              emptyList(),          "Wrong criticalExtensions");
        assertEquals(header.getAdditionalHeaders(),               emptyMap(),           "Wrong additionalHeaders");
    }

    @Test
    public void testSection3_1_B()
    throws Exception {
        final String json = "{\"alg\":\"none\"}";
        final JWSHeader header = mapper.readValue(json, JWSHeader.class);
        validateObject(json, header);

        assertEquals(header.getAlgorithm(),                       NONE,                 "Wrong algorithm");
        assertEquals(header.getMediaType(),                       null,                 "Wrong type");
        assertEquals(header.getContentMediaType(),                null,                 "Wrong contentType");
        assertEquals(header.getKeyId(),                           null,                 "Wrong keyID");
        assertEquals(header.getJsonWebKey(),                      null,                 "Wrong jwk");
        assertEquals(header.getJsonWebKeySetUrl(),                null,                 "Wrong jwkSetURL");
        assertEquals(header.getX509CertificateChain(),            emptyList(),          "Wrong x509CertificateChain");
        assertEquals(header.getX509CertificateThumbprint(),       null,                 "Wrong x509CertificateThumbprint");
        assertEquals(header.getX509CertificateThumbprintSHA256(), null,                 "Wrong x509CertificateThumbprintSHA256");
        assertEquals(header.getX509Url(),                         null,                 "Wrong x509URI");
        assertEquals(header.getCriticalExtensions(),              emptyList(),          "Wrong criticalExtensions");
        assertEquals(header.getAdditionalHeaders(),               emptyMap(),           "Wrong additionalHeaders");
    }

    @Test
    public void testSection4_1_11()
    throws Exception {
        final String json = "{\"alg\":\"ES256\",\"crit\":[\"exp\"],\"exp\":1363284000}";
        final JWSHeader header = mapper.readValue(json, JWSHeader.class);
        validateObject(json, header);

        assertEquals(header.getAlgorithm(),                       ES256,                "Wrong algorithm");
        assertEquals(header.getMediaType(),                       null,                 "Wrong type");
        assertEquals(header.getContentMediaType(),                null,                 "Wrong contentType");
        assertEquals(header.getKeyId(),                           null,                 "Wrong keyID");
        assertEquals(header.getJsonWebKey(),                      null,                 "Wrong jwk");
        assertEquals(header.getJsonWebKeySetUrl(),                null,                 "Wrong jwkSetURL");
        assertEquals(header.getX509CertificateChain(),            emptyList(),          "Wrong x509CertificateChain");
        assertEquals(header.getX509CertificateThumbprint(),       null,                 "Wrong x509CertificateThumbprint");
        assertEquals(header.getX509CertificateThumbprintSHA256(), null,                 "Wrong x509CertificateThumbprintSHA256");
        assertEquals(header.getX509Url(),                         null,                 "Wrong x509URI");
        assertEquals(header.getCriticalExtensions(),              singletonList("exp"), "Wrong criticalExtensions");
        assertEquals(header.getAdditionalHeaders(),               singletonMap("exp", new Integer(1363284000)),
                                                                                        "Wrong additionalHeaders");
    }

    @Test
    public void testFullJWSHeader()
    throws Exception {
        final URL url = getResource("full.json");
        final JWSHeader header = mapper.readValue(url, JWSHeader.class);
        validateObject(url, header);

        final List<String> criticalExtensions = new ArrayList<String>(){{
            this.add("first");
            this.add("second");
        }};

        final Map<String, Object> additionalHeaders = new HashMap<String, Object>(){{
            put("first", "The first critical header");
            put("second", "The second critical header");
            put("third", "The third header is not critical");
        }};

        mapper.writeValue(System.out, header);

        assertEquals(header.getAlgorithm(),                       PS512,                                          "Wrong algorithm");
        assertEquals(header.getMediaType(),                       APPLICATION_JWS_TYPE,                           "Wrong type");
        assertEquals(header.getContentMediaType(),                TEXT_HTML_TYPE,                                 "Wrong contentType");
        assertEquals(header.getKeyId(),                           "the quick brown fox jumped over the lazy dog", "Wrong keyID");
        assertEquals(header.getJsonWebKeySetUrl(),                URI.create("https://example.org/a-simple.jku"), "Wrong jwkSetURL");
        assertEquals(header.getX509CertificateChain().size(),                   3,                                "Wrong x509CertificateChain");
        assertEquals(header.getX509CertificateThumbprint().length(),            20,                               "Wrong x509CertificateThumbprint");
        assertEquals(header.getX509CertificateThumbprintSHA256().length(),      32,                               "Wrong x509CertificateThumbprintSHA256");
        assertEquals(header.getX509Url(),                         URI.create("https://example.org/a-simple.pem"), "Wrong x509URI");
        assertEquals(header.getCriticalExtensions(),              criticalExtensions,                             "Wrong criticalExtensions");
        assertEquals(header.getAdditionalHeaders(),               additionalHeaders,                              "Wrong additionalHeaders");

        assertEquals(header.getX509CertificateChain().get(0).getSubjectDN().toString(),
                     "SERIALNUMBER=07969287, CN=Go Daddy Secure Certification Authority, OU=http://certificates.godaddy.com/repository, O=\"GoDaddy.com, Inc.\", L=Scottsdale, ST=Arizona, C=US",
                     "Wrong subject for X509 certificate [0]");
        assertEquals(header.getX509CertificateChain().get(1).getSubjectDN().toString(),
                     "OU=Go Daddy Class 2 Certification Authority, O=\"The Go Daddy Group, Inc.\", C=US",
                     "Wrong subject for X509 certificate [1]");
        assertEquals(header.getX509CertificateChain().get(2).getSubjectDN().toString(),
                     "EMAILADDRESS=info@valicert.com, CN=http://www.valicert.com/, OU=ValiCert Class 2 Policy Validation Authority, O=\"ValiCert, Inc.\", L=ValiCert Validation Network",
                     "Wrong subject for X509 certificate [2]");

        /* Copied in from JWK secition B */
        assertNotNull(header.getJsonWebKey(), "Wrong jwk");
        assertTrue(header.getJsonWebKey() instanceof RSAPublicJWK, "Wrong jwk class");

        final RSAPublicJWK rsa = (RSAPublicJWK) header.getJsonWebKey();

        assertEquals(rsa.getAlgorithm(),                       null,                "Wrong algorithm");
        assertEquals(rsa.getKeyId(),                           "1b94c",             "Wrong key ID");
        assertEquals(rsa.getKeyOperations(),                   EMPTY_LIST,          "Wrong key operations");
        assertEquals(rsa.getKeyType(),                         JWKKeyType.RSA,      "Wrong key type");
        assertEquals(rsa.getPublicKeyUse(),                    JWKPublicKeyUse.SIG, "Wrong public key use");
        assertEquals(rsa.getX509CertificateChain().size(),     1,                   "Wrong certificate chain");
        assertEquals(rsa.getX509CertificateThumbprint(),       null,                "Wrong certificate thumbprint");
        assertEquals(rsa.getX509CertificateThumbprintSHA256(), null,                "Wrong certificate thumbprint (sha256)");
        assertEquals(rsa.getX509Url(),                         null,                "Wrong X509 URL");

        final BigInteger n = parseBigInteger("vrjOfz9Ccdgx5nQudyhdoR17V-IubWMeOZCwX_jj0hgAsz2J_pqYW08PLbK_PdiVGKPrqzmDIsLI7sA25VEnHU1uCLNwBuUiCO11_-7dYbsr4iJmG0Qu2j8DsVyT1azpJC_NG84Ty5KKthuCaPod7iI7w0LK9orSMhBEwwZDCxTWq4aYWAchc8t-emd9qOvWtVMDC2BXksRngh6X5bUYLy6AyHKvj-nUy1wgzjYQDwHMTplCoLtU-o-8SNnZ1tmRoGE9uJkBLdh5gFENabWnU5m1ZqZPdwS-qo-meMvVfJb6jJVWRpl2SUtCnYG2C32qvbWbjZ_jBPD5eunqsIo1vQ");
        final BigInteger e = parseBigInteger("AQAB");
        assertEquals(rsa.getModulus(),                         n,                   "Wrong modulus");
        assertEquals(rsa.getPublicExponent(),                  e,                   "Wrong public exponent");

        final X509Certificate cert = rsa.getX509CertificateChain().get(0);
        assertEquals(cert.getSubjectDN().toString(), "CN=Brian Campbell, O=Ping Identity Corp., L=Denver, ST=CO, C=US", "Wrong certificate subject");
        assertEquals(((RSAPublicKey) cert.getPublicKey()).getModulus(), n, "Wrong modulus");
        assertEquals(((RSAPublicKey) cert.getPublicKey()).getPublicExponent(), e, "Wrong public exponent");

        validateObject(url, header);
    }
}
