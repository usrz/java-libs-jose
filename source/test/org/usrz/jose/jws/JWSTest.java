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

import static java.util.Collections.emptyList;
import static java.util.Collections.emptyMap;
import static java.util.Collections.singletonList;
import static java.util.Collections.singletonMap;
import static javax.ws.rs.core.MediaType.TEXT_HTML_TYPE;
import static org.usrz.jose.JOSEMediaTypes.APPLICATION_JWS_TYPE;
import static org.usrz.jose.JOSEMediaTypes.APPLICATION_JWT_TYPE;
import static org.usrz.jose.jws.JWSAlgorithm.ES256;
import static org.usrz.jose.jws.JWSAlgorithm.HS256;
import static org.usrz.jose.jws.JWSAlgorithm.NONE;
import static org.usrz.jose.jws.JWSAlgorithm.PS512;

import java.net.URI;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.testng.annotations.Test;
import org.usrz.jose.JOSEObject;
import org.usrz.jose.jackson.JOSEObjectMapper;
import org.usrz.libs.testing.AbstractTest;

import com.fasterxml.jackson.core.TreeNode;
import com.fasterxml.jackson.core.util.DefaultPrettyPrinter;


public class JWSTest extends AbstractTest {

    private final JOSEObjectMapper mapper = new JOSEObjectMapper();

    protected URL getResource(String name) {
        final URL url = this.getClass().getResource(name);
        assertNotNull(url, "Resource " + name + " not found");
        return url;
    }

    protected void validateObject(URL url, Object object)
    throws Exception {
        final TreeNode actual = mapper.valueToTree(object);
        final TreeNode expected = mapper.readTree(url);

        if (!actual.equals(expected)) {
            final String actualString = mapper.writer(new DefaultPrettyPrinter()).writeValueAsString(actual);
            final String expectedString = mapper.writer(new DefaultPrettyPrinter()).writeValueAsString(expected);
            throw new AssertionError("Tree differs: " + url + "\n>>> EXPECTED >>>\n" + expectedString + "\n<<< ACTUAL <<<\n" + actualString);
        } else {
            System.err.println("Validated " + url);
            System.err.println(mapper.writer(new DefaultPrettyPrinter()).writeValueAsString(actual));
        }
    }

    /* ====================================================================== */

    @Test
    public void testSection3_1_example_1()
    throws Exception {
        final URL url = getResource("jws-section-3.1-example1.json");
        final JOSEObject<?> object = mapper.readValue(url, JOSEObject.class);
        validateObject(url, object);

        assertTrue(object instanceof JWSHeader);
        JWSHeader header = (JWSHeader) object;

        assertEquals(header.getAlgorithm(),                       HS256,                "Wrong algorithm");
        assertEquals(header.getMediaType(),                            APPLICATION_JWT_TYPE, "Wrong type");
        assertEquals(header.getContentMediaType(),                     null,                 "Wrong contentType");
        assertEquals(header.getKeyId(),                           null,                 "Wrong keyID");
        assertEquals(header.getJsonWebKey(),                             null,                 "Wrong jwk");
        assertEquals(header.getJsonWebKeySetUrl(),                       null,                 "Wrong jwkSetURL");
        assertEquals(header.getX509CertificateChain(),            null,                 "Wrong x509CertificateChain");
        assertEquals(header.getX509CertificateThumbprint(),       null,                 "Wrong x509CertificateThumbprint");
        assertEquals(header.getX509CertificateThumbprintSHA256(), null,                 "Wrong x509CertificateThumbprintSHA256");
        assertEquals(header.getX509Url(),                         null,                 "Wrong x509URI");
        assertEquals(header.getCriticalExtensions(),              emptyList(),          "Wrong criticalExtensions");
        assertEquals(header.getAdditionalHeaders(),               emptyMap(),           "Wrong additionalHeaders");
    }

    @Test
    public void testSection3_1_example_2()
    throws Exception {
        final URL url = getResource("jws-section-3.1-example2.json");
        final JOSEObject<?> object = mapper.readValue(url, JOSEObject.class);
        validateObject(url, object);

        assertTrue(object instanceof JWSHeader);
        JWSHeader header = (JWSHeader) object;

        assertEquals(header.getAlgorithm(),                       NONE,                 "Wrong algorithm");
        assertEquals(header.getMediaType(),                            null,                 "Wrong type");
        assertEquals(header.getContentMediaType(),                     null,                 "Wrong contentType");
        assertEquals(header.getKeyId(),                           null,                 "Wrong keyID");
        assertEquals(header.getJsonWebKey(),                             null,                 "Wrong jwk");
        assertEquals(header.getJsonWebKeySetUrl(),                       null,                 "Wrong jwkSetURL");
        assertEquals(header.getX509CertificateChain(),            null,                 "Wrong x509CertificateChain");
        assertEquals(header.getX509CertificateThumbprint(),       null,                 "Wrong x509CertificateThumbprint");
        assertEquals(header.getX509CertificateThumbprintSHA256(), null,                 "Wrong x509CertificateThumbprintSHA256");
        assertEquals(header.getX509Url(),                         null,                 "Wrong x509URI");
        assertEquals(header.getCriticalExtensions(),              emptyList(),          "Wrong criticalExtensions");
        assertEquals(header.getAdditionalHeaders(),               emptyMap(),           "Wrong additionalHeaders");
    }

    @Test
    public void testSection4_1_11_critical_header()
    throws Exception {
        final URL url = getResource("jws-section-4.1.11-critical-header.json");
        final JOSEObject<?> object = mapper.readValue(url, JOSEObject.class);
        validateObject(url, object);

        assertTrue(object instanceof JWSHeader);
        JWSHeader header = (JWSHeader) object;

        assertEquals(header.getAlgorithm(),                       ES256,                "Wrong algorithm");
        assertEquals(header.getMediaType(),                            null,                 "Wrong type");
        assertEquals(header.getContentMediaType(),                     null,                 "Wrong contentType");
        assertEquals(header.getKeyId(),                           null,                 "Wrong keyID");
        assertEquals(header.getJsonWebKey(),                             null,                 "Wrong jwk");
        assertEquals(header.getJsonWebKeySetUrl(),                       null,                 "Wrong jwkSetURL");
        assertEquals(header.getX509CertificateChain(),            null,                 "Wrong x509CertificateChain");
        assertEquals(header.getX509CertificateThumbprint(),       null,                 "Wrong x509CertificateThumbprint");
        assertEquals(header.getX509CertificateThumbprintSHA256(), null,                 "Wrong x509CertificateThumbprintSHA256");
        assertEquals(header.getX509Url(),                         null,                 "Wrong x509URI");
        assertEquals(header.getCriticalExtensions(),              singletonList("exp"), "Wrong criticalExtensions");
        assertEquals(header.getAdditionalHeaders(),               singletonMap("exp", new Integer(1363284000)),
                                                                                        "Wrong additionalHeaders");
    }

    @Test
    public void testFull()
    throws Exception {
        final URL url = getResource("full.json");
        final JOSEObject<?> object = mapper.readValue(url, JOSEObject.class);

        assertTrue(object instanceof JWSHeader);
        JWSHeader header = (JWSHeader) object;

        final List<String> criticalExtensions = new ArrayList<String>(){{
            this.add("first");
            this.add("second");
        }};

        final Map<String, Object> additionalHeaders = new HashMap<String, Object>(){{
            put("first", "The first critical header");
            put("second", "The second critical header");
            put("third", "The third header is not critical");
        }};

        mapper.writeValue(System.out, object);

        // TODO: JWK and test!!!

        assertEquals(header.getAlgorithm(),                       PS512,                                          "Wrong algorithm");
        assertEquals(header.getMediaType(),                            APPLICATION_JWS_TYPE,                           "Wrong type");
        assertEquals(header.getContentMediaType(),                     TEXT_HTML_TYPE,                                 "Wrong contentType");
        assertEquals(header.getKeyId(),                           "the quick brown fox jumped over the lazy dog", "Wrong keyID");
        assertEquals(header.getJsonWebKey(),                             null,                                           "Wrong jwk");
        assertEquals(header.getJsonWebKeySetUrl(),                       URI.create("https://example.org/a-simple.jku"), "Wrong jwkSetURL");
        assertEquals(header.getX509CertificateChain().size(),                   3,                                "Wrong x509CertificateChain");
        assertEquals(header.getX509CertificateThumbprint().length,              20,                               "Wrong x509CertificateThumbprint");
        assertEquals(header.getX509CertificateThumbprintSHA256().length,        32,                               "Wrong x509CertificateThumbprintSHA256");
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

        validateObject(url, object);
    }
}
