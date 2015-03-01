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
package org.usrz.jose.jwk;

import static java.util.Collections.EMPTY_LIST;

import java.net.URL;
import java.util.List;

import org.testng.annotations.Test;
import org.usrz.jose.AbstractTestParse;
import org.usrz.jose.core.Bytes;
import org.usrz.jose.jwe.JWEAlgorithm;
import org.usrz.jose.jwk.oct.OctetSequenceJWK;
import org.usrz.libs.utils.codecs.Base64Codec;

public class JWKTest extends AbstractTestParse {

    @Test
    public void testAppendix_A3()
    throws Exception {
        final URL url = getResource("jwk-appendix-a3-symmetric-keys.json");
        final JWKSet keySet = mapper.readValue(url, JWKSet.class);
        validateObject(url, keySet);

        assertNotNull(keySet);
        assertNotNull(keySet.getKeys());

        final List<JWK<?>> keys = keySet.getKeys();

        assertEquals(keys.size(), 2);
        assertTrue(keys.get(0) instanceof OctetSequenceJWK, "Wrong type for key 0");
        assertTrue(keys.get(1) instanceof OctetSequenceJWK, "Wrong type for key 1");

        final OctetSequenceJWK key0 = (OctetSequenceJWK) keys.get(0);

        final Bytes b0 = new Bytes(Base64Codec.BASE_64.decode("GawgguFyGrWKav7AX4VKUg"));
        assertEquals(key0.getAlgorithm(),                     JWEAlgorithm.A128KW, "Wrong algorithm");
        assertNull  (key0.getKeyId(),                                              "Wrong key ID");
        assertEquals(key0.getKeyOperations(),                 EMPTY_LIST,          "Wrong key operations");
        assertEquals(key0.getKeyType(),                       JWKKeyType.OCT,      "Wrong key type");
        assertEquals(key0.getKeyValue(),                      b0,                  "Wrong key value");
        assertNull  (key0.getPublicKeyUse(),                                       "Wrong public key use");
        assertEquals(key0.getX509CertificateChain(),          EMPTY_LIST,          "Wrong certificate chain");
        assertNull  (key0.getX509CertificateThumbprint(),                          "Wrong certificate thumbprint");
        assertNull  (key0.getX509CertificateThumbprintSHA256(),                    "Wrong certificate thumbprint (sha256)");
        assertNull  (key0.getX509Url(),                                            "Wrong X509 URL");

        final OctetSequenceJWK key1 = (OctetSequenceJWK) keys.get(1);
        final Bytes b1 = new Bytes(Base64Codec.BASE_64.decode("AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"));
        assertNull  (key1.getAlgorithm(),                                          "Wrong algorithm");
        assertEquals(key1.getKeyId(),          "HMAC key used in JWS A.1 example", "Wrong key ID");
        assertEquals(key0.getKeyOperations(),                 EMPTY_LIST,          "Wrong key operations");
        assertEquals(key1.getKeyType(),                       JWKKeyType.OCT,      "Wrong key type");
        assertEquals(key1.getKeyValue(),                      b1,                  "Wrong key value");
        assertNull  (key1.getPublicKeyUse(),                                       "Wrong public key use");
        assertEquals(key1.getX509CertificateChain(),          EMPTY_LIST,          "Wrong certificate chain");
        assertNull  (key1.getX509CertificateThumbprint(),                          "Wrong certificate thumbprint");
        assertNull  (key1.getX509CertificateThumbprintSHA256(),                    "Wrong certificate thumbprint (sha256)");
        assertNull  (key1.getX509Url(),                                            "Wrong X509 URL");
    }
}

//{
//    "keys": [
//      {
//        "kty": "oct",
//        "alg": "A128KW",
//        "k": "GawgguFyGrWKav7AX4VKUg"
//      },
//      {
//        "kty": "oct",
//        "k": "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
//        "kid": "HMAC key used in JWS A.1 example"
//      }
//    ]
//  }
