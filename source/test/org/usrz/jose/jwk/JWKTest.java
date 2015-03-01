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

import java.math.BigInteger;
import java.net.URL;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.List;

import org.testng.annotations.Test;
import org.usrz.jose.AbstractTestParse;
import org.usrz.jose.core.Bytes;
import org.usrz.jose.jwe.JWEAlgorithm;
import org.usrz.jose.jwk.ec.ECCurve;
import org.usrz.jose.jwk.ec.ECPrivateJWK;
import org.usrz.jose.jwk.ec.ECPublicJWK;
import org.usrz.jose.jwk.oct.OctetSequenceJWK;
import org.usrz.jose.jwk.rsa.RSAPrivateJWK;
import org.usrz.jose.jwk.rsa.RSAPublicJWK;
import org.usrz.jose.jws.JWSAlgorithm;

public class JWKTest extends AbstractTestParse {

    @Test
    public void testAppendix_A1()
    throws Exception {
        final URL url = getResource("jwk-appendix-a1-public-keys.json");
        final JWKSet keySet = mapper.readValue(url, JWKSet.class);
        validateObject(url, keySet);

        assertNotNull(keySet);
        assertNotNull(keySet.getKeys());

        final List<JWK<?>> keys = keySet.getKeys();

        assertEquals(keys.size(), 2);
        assertEquals(keys.get(0).getKeyType(), JWKKeyType.EC, "Wrong type for key 0");
        assertEquals(keys.get(1).getKeyType(), JWKKeyType.RSA, "Wrong type for key 1");
        assertTrue(keys.get(0) instanceof ECPublicJWK, "Wrong class for key 0");
        assertTrue(keys.get(1) instanceof RSAPublicJWK, "Wrong class for key 1");

        final ECPublicJWK key0 = (ECPublicJWK) keys.get(0);
        assertNull  (key0.getAlgorithm(),                                          "Wrong algorithm");
        assertEquals(key0.getKeyId(),                         "1",                 "Wrong key ID");
        assertEquals(key0.getKeyOperations(),                 EMPTY_LIST,          "Wrong key operations");
        assertEquals(key0.getKeyType(),                       JWKKeyType.EC,       "Wrong key type");
        assertEquals(key0.getPublicKeyUse(),                  JWKPublicKeyUse.ENC, "Wrong public key use");
        assertEquals(key0.getX509CertificateChain(),          EMPTY_LIST,          "Wrong certificate chain");
        assertNull  (key0.getX509CertificateThumbprint(),                          "Wrong certificate thumbprint");
        assertNull  (key0.getX509CertificateThumbprintSHA256(),                    "Wrong certificate thumbprint (sha256)");
        assertNull  (key0.getX509Url(),                                            "Wrong X509 URL");

        final BigInteger x = parseBigInteger("MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4");
        final BigInteger y = parseBigInteger("4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM");
        assertEquals(key0.getCurve(),                         ECCurve.P_256,       "Wrong EC Curve");
        assertEquals(key0.getXCoordinate(),                   x,                   "Wrong X coordinate");
        assertEquals(key0.getYCoordinate(),                   y,                   "Wrong Y coordinate");

        final RSAPublicJWK key1 = (RSAPublicJWK) keys.get(1);
        assertEquals(key1.getAlgorithm(),                     JWSAlgorithm.RS256,  "Wrong algorithm");
        assertEquals(key1.getKeyId(),                         "2011-04-29",        "Wrong key ID");
        assertEquals(key1.getKeyOperations(),                 EMPTY_LIST,          "Wrong key operations");
        assertEquals(key1.getKeyType(),                       JWKKeyType.RSA,      "Wrong key type");
        assertNull  (key1.getPublicKeyUse(),                                       "Wrong public key use");
        assertEquals(key1.getX509CertificateChain(),          EMPTY_LIST,          "Wrong certificate chain");
        assertNull  (key1.getX509CertificateThumbprint(),                          "Wrong certificate thumbprint");
        assertNull  (key1.getX509CertificateThumbprintSHA256(),                    "Wrong certificate thumbprint (sha256)");
        assertNull  (key1.getX509Url(),                                            "Wrong X509 URL");

        final BigInteger n = parseBigInteger("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw");
        final BigInteger e = parseBigInteger("AQAB");
        assertEquals(key1.getModulus(),                       n,                   "Wrong modulus");
        assertEquals(key1.getPublicExponent(),                e,                   "Wrong public exponent");
    }

    @Test
    public void testAppendix_A2()
    throws Exception {
        final URL url = getResource("jwk-appendix-a2-private-keys.json");
        final JWKSet keySet = mapper.readValue(url, JWKSet.class);
        validateObject(url, keySet);

        assertNotNull(keySet);
        assertNotNull(keySet.getKeys());

        final List<JWK<?>> keys = keySet.getKeys();

        assertEquals(keys.size(), 2);
        assertEquals(keys.get(0).getKeyType(), JWKKeyType.EC, "Wrong type for key 0");
        assertEquals(keys.get(1).getKeyType(), JWKKeyType.RSA, "Wrong type for key 1");
        assertTrue(keys.get(0) instanceof ECPrivateJWK, "Wrong class for key 0");
        assertTrue(keys.get(1) instanceof RSAPrivateJWK, "Wrong class for key 1");

        final ECPrivateJWK key0 = (ECPrivateJWK) keys.get(0);
        assertNull  (key0.getAlgorithm(),                                          "Wrong algorithm");
        assertEquals(key0.getKeyId(),                         "1",                 "Wrong key ID");
        assertEquals(key0.getKeyOperations(),                 EMPTY_LIST,          "Wrong key operations");
        assertEquals(key0.getKeyType(),                       JWKKeyType.EC,       "Wrong key type");
        assertEquals(key0.getPublicKeyUse(),                  JWKPublicKeyUse.ENC, "Wrong public key use");
        assertEquals(key0.getX509CertificateChain(),          EMPTY_LIST,          "Wrong certificate chain");
        assertNull  (key0.getX509CertificateThumbprint(),                          "Wrong certificate thumbprint");
        assertNull  (key0.getX509CertificateThumbprintSHA256(),                    "Wrong certificate thumbprint (sha256)");
        assertNull  (key0.getX509Url(),                                            "Wrong X509 URL");

        final BigInteger x = parseBigInteger("MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4");
        final BigInteger y = parseBigInteger("4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM");
        final BigInteger d = parseBigInteger("870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE");
        assertEquals(key0.getCurve(),                         ECCurve.P_256,       "Wrong EC Curve");
        assertEquals(key0.getXCoordinate(),                   x,                   "Wrong X coordinate");
        assertEquals(key0.getYCoordinate(),                   y,                   "Wrong Y coordinate");
        assertEquals(key0.getEccPrivateKey(),                 d,                   "Wrong ECC Private Key");

        final RSAPrivateJWK key1 = (RSAPrivateJWK) keys.get(1);
        assertEquals(key1.getAlgorithm(),                     JWSAlgorithm.RS256,  "Wrong algorithm");
        assertEquals(key1.getKeyId(),                         "2011-04-29",        "Wrong key ID");
        assertEquals(key1.getKeyOperations(),                 EMPTY_LIST,          "Wrong key operations");
        assertEquals(key1.getKeyType(),                       JWKKeyType.RSA,      "Wrong key type");
        assertNull  (key1.getPublicKeyUse(),                                       "Wrong public key use");
        assertEquals(key1.getX509CertificateChain(),          EMPTY_LIST,          "Wrong certificate chain");
        assertNull  (key1.getX509CertificateThumbprint(),                          "Wrong certificate thumbprint");
        assertNull  (key1.getX509CertificateThumbprintSHA256(),                    "Wrong certificate thumbprint (sha256)");
        assertNull  (key1.getX509Url(),                                            "Wrong X509 URL");

        final BigInteger n = parseBigInteger("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw");
        final BigInteger e = parseBigInteger("AQAB");
        final BigInteger dd = parseBigInteger("X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q");
        final BigInteger p = parseBigInteger("83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs");
        final BigInteger q = parseBigInteger("3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyumqjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk");
        final BigInteger dp = parseBigInteger("G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_NmtuYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0");
        final BigInteger dq = parseBigInteger("s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUUvMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk");
        final BigInteger qi = parseBigInteger("GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU");
        assertEquals(key1.getModulus(),                       n,                   "Wrong modulus");
        assertEquals(key1.getPublicExponent(),                e,                   "Wrong public exponent");
        assertEquals(key1.getPrivateExponent(),               dd,                  "Wrong private exponent");
        assertEquals(key1.getPrimeP(),                        p,                   "Wrong prime p");
        assertEquals(key1.getPrimeQ(),                        q,                   "Wrong prime q");
        assertEquals(key1.getPrimeExponentP(),                dp,                  "Wrong prime exponent p");
        assertEquals(key1.getPrimeExponentQ(),                dq,                  "Wrong prime exponent q");
        assertEquals(key1.getCrtCoefficient(),                qi,                  "Wrong crt coefficient");
    }


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
        assertEquals(keys.get(0).getKeyType(), JWKKeyType.OCT, "Wrong type for key 0");
        assertEquals(keys.get(1).getKeyType(), JWKKeyType.OCT, "Wrong type for key 1");
        assertTrue(keys.get(0) instanceof OctetSequenceJWK, "Wrong class for key 0");
        assertTrue(keys.get(1) instanceof OctetSequenceJWK, "Wrong class for key 1");

        final OctetSequenceJWK key0 = (OctetSequenceJWK) keys.get(0);

        final Bytes b0 = parseBytes("GawgguFyGrWKav7AX4VKUg");
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
        final Bytes b1 = parseBytes("AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow");
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

    @Test
    public void testAppendix_B()
    throws Exception {
        final URL url = getResource("jwk-appendix-b-x5c-parameter.json");
        final JWK<?> key = mapper.readValue(url, JWK.class);
        validateObject(url, key);

        assertEquals(key.getKeyType(), JWKKeyType.RSA, "Wrong type for key");
        assertTrue(key instanceof RSAPublicJWK, "Wrong class for key");

        final RSAPublicJWK rsa = (RSAPublicJWK) key;

        assertNull  (rsa.getAlgorithm(),                                          "Wrong algorithm");
        assertEquals(rsa.getKeyId(),                         "1b94c",             "Wrong key ID");
        assertEquals(rsa.getKeyOperations(),                 EMPTY_LIST,          "Wrong key operations");
        assertEquals(rsa.getKeyType(),                       JWKKeyType.RSA,      "Wrong key type");
        assertEquals(rsa.getPublicKeyUse(),                  JWKPublicKeyUse.SIG, "Wrong public key use");
        assertEquals(rsa.getX509CertificateChain().size(),   1,                   "Wrong certificate chain");
        assertNull  (rsa.getX509CertificateThumbprint(),                          "Wrong certificate thumbprint");
        assertNull  (rsa.getX509CertificateThumbprintSHA256(),                    "Wrong certificate thumbprint (sha256)");
        assertNull  (rsa.getX509Url(),                                            "Wrong X509 URL");

        final BigInteger n = parseBigInteger("vrjOfz9Ccdgx5nQudyhdoR17V-IubWMeOZCwX_jj0hgAsz2J_pqYW08PLbK_PdiVGKPrqzmDIsLI7sA25VEnHU1uCLNwBuUiCO11_-7dYbsr4iJmG0Qu2j8DsVyT1azpJC_NG84Ty5KKthuCaPod7iI7w0LK9orSMhBEwwZDCxTWq4aYWAchc8t-emd9qOvWtVMDC2BXksRngh6X5bUYLy6AyHKvj-nUy1wgzjYQDwHMTplCoLtU-o-8SNnZ1tmRoGE9uJkBLdh5gFENabWnU5m1ZqZPdwS-qo-meMvVfJb6jJVWRpl2SUtCnYG2C32qvbWbjZ_jBPD5eunqsIo1vQ");
        final BigInteger e = parseBigInteger("AQAB");
        assertEquals(rsa.getModulus(),                       n,                   "Wrong modulus");
        assertEquals(rsa.getPublicExponent(),                e,                   "Wrong public exponent");

        final X509Certificate cert = rsa.getX509CertificateChain().get(0);
        assertEquals(cert.getSubjectDN().toString(), "CN=Brian Campbell, O=Ping Identity Corp., L=Denver, ST=CO, C=US", "Wrong certificate subject");
        assertEquals(((RSAPublicKey) cert.getPublicKey()).getModulus(), n, "Wrong modulus");
        assertEquals(((RSAPublicKey) cert.getPublicKey()).getPublicExponent(), e, "Wrong public exponent");

    }

    @Test
    public void testAppendix_C1()
    throws Exception {
        final URL url = getResource("jwk-appendix-c1-extra-example.json");
        final JWK<?> key = mapper.readValue(url, JWK.class);
        validateObject(url, key);

        assertEquals(key.getKeyType(), JWKKeyType.RSA, "Wrong type for key");
        assertTrue(key instanceof RSAPrivateJWK, "Wrong class for key");

        final RSAPrivateJWK rsa = (RSAPrivateJWK) key;

        assertNull  (rsa.getAlgorithm(),                                          "Wrong algorithm");
        assertEquals(rsa.getKeyId(),                        "juliet@capulet.lit", "Wrong key ID");
        assertEquals(rsa.getKeyOperations(),                 EMPTY_LIST,          "Wrong key operations");
        assertEquals(rsa.getKeyType(),                       JWKKeyType.RSA,      "Wrong key type");
        assertEquals(rsa.getPublicKeyUse(),                  JWKPublicKeyUse.ENC, "Wrong public key use");
        assertEquals(rsa.getX509CertificateChain(),          EMPTY_LIST,          "Wrong certificate chain");
        assertNull  (rsa.getX509CertificateThumbprint(),                          "Wrong certificate thumbprint");
        assertNull  (rsa.getX509CertificateThumbprintSHA256(),                    "Wrong certificate thumbprint (sha256)");
        assertNull  (rsa.getX509Url(),                                            "Wrong X509 URL");

        final BigInteger n = parseBigInteger("t6Q8PWSi1dkJj9hTP8hNYFlvadM7DflW9mWepOJhJ66w7nyoK1gPNqFMSQRyO125Gp-TEkodhWr0iujjHVx7BcV0llS4w5ACGgPrcAd6ZcSR0-Iqom-QFcNP8Sjg086MwoqQU_LYywlAGZ21WSdS_PERyGFiNnj3QQlO8Yns5jCtLCRwLHL0Pb1fEv45AuRIuUfVcPySBWYnDyGxvjYGDSM-AqWS9zIQ2ZilgT-GqUmipg0XOC0Cc20rgLe2ymLHjpHciCKVAbY5-L32-lSeZO-Os6U15_aXrk9Gw8cPUaX1_I8sLGuSiVdt3C_Fn2PZ3Z8i744FPFGGcG1qs2Wz-Q");
        final BigInteger e = parseBigInteger("AQAB");
        final BigInteger d = parseBigInteger("GRtbIQmhOZtyszfgKdg4u_N-R_mZGU_9k7JQ_jn1DnfTuMdSNprTeaSTyWfSNkuaAwnOEbIQVy1IQbWVV25NY3ybc_IhUJtfri7bAXYEReWaCl3hdlPKXy9UvqPYGR0kIXTQRqns-dVJ7jahlI7LyckrpTmrM8dWBo4_PMaenNnPiQgO0xnuToxutRZJfJvG4Ox4ka3GORQd9CsCZ2vsUDmsXOfUENOyMqADC6p1M3h33tsurY15k9qMSpG9OX_IJAXmxzAh_tWiZOwk2K4yxH9tS3Lq1yX8C1EWmeRDkK2ahecG85-oLKQt5VEpWHKmjOi_gJSdSgqcN96X52esAQ");
        final BigInteger p = parseBigInteger("2rnSOV4hKSN8sS4CgcQHFbs08XboFDqKum3sc4h3GRxrTmQdl1ZK9uw-PIHfQP0FkxXVrx-WE-ZEbrqivH_2iCLUS7wAl6XvARt1KkIaUxPPSYB9yk31s0Q8UK96E3_OrADAYtAJs-M3JxCLfNgqh56HDnETTQhH3rCT5T3yJws");
        final BigInteger q = parseBigInteger("1u_RiFDP7LBYh3N4GXLT9OpSKYP0uQZyiaZwBtOCBNJgQxaj10RWjsZu0c6Iedis4S7B_coSKB0Kj9PaPaBzg-IySRvvcQuPamQu66riMhjVtG6TlV8CLCYKrYl52ziqK0E_ym2QnkwsUX7eYTB7LbAHRK9GqocDE5B0f808I4s");
        final BigInteger dp = parseBigInteger("KkMTWqBUefVwZ2_Dbj1pPQqyHSHjj90L5x_MOzqYAJMcLMZtbUtwKqvVDq3tbEo3ZIcohbDtt6SbfmWzggabpQxNxuBpoOOf_a_HgMXK_lhqigI4y_kqS1wY52IwjUn5rgRrJ-yYo1h41KR-vz2pYhEAeYrhttWtxVqLCRViD6c");
        final BigInteger dq = parseBigInteger("AvfS0-gRxvn0bwJoMSnFxYcK1WnuEjQFluMGfwGitQBWtfZ1Er7t1xDkbN9GQTB9yqpDoYaN06H7CFtrkxhJIBQaj6nkF5KKS3TQtQ5qCzkOkmxIe3KRbBymXxkb5qwUpX5ELD5xFc6FeiafWYY63TmmEAu_lRFCOJ3xDea-ots");
        final BigInteger qi = parseBigInteger("lSQi-w9CpyUReMErP1RsBLk7wNtOvs5EQpPqmuMvqW57NBUczScEoPwmUqqabu9V0-Py4dQ57_bapoKRu1R90bvuFnU63SHWEFglZQvJDMeAvmj4sm-Fp0oYu_neotgQ0hzbI5gry7ajdYy9-2lNx_76aBZoOUu9HCJ-UsfSOI8");
        assertEquals(rsa.getModulus(),                       n,                   "Wrong modulus");
        assertEquals(rsa.getPublicExponent(),                e,                   "Wrong public exponent");
        assertEquals(rsa.getPrivateExponent(),               d,                   "Wrong private exponent");
        assertEquals(rsa.getPrimeP(),                        p,                   "Wrong prime p");
        assertEquals(rsa.getPrimeQ(),                        q,                   "Wrong prime q");
        assertEquals(rsa.getPrimeExponentP(),                dp,                  "Wrong prime exponent p");
        assertEquals(rsa.getPrimeExponentQ(),                dq,                  "Wrong prime exponent q");
        assertEquals(rsa.getCrtCoefficient(),                qi,                  "Wrong crt coefficient");
    }


    @Test
    public void testSection_3()
    throws Exception {
        final URL url = getResource("jwk-section-3-example.json");
        final JWK<?> key = mapper.readValue(url, JWK.class);
        validateObject(url, key);

        assertEquals(key.getKeyType(), JWKKeyType.EC, "Wrong type for key");
        assertTrue(key instanceof ECPublicJWK, "Wrong class for key");

        final ECPublicJWK ec = (ECPublicJWK) key;

        assertNull  (ec.getAlgorithm(),                                          "Wrong algorithm");
        assertEquals(ec.getKeyId(),        "Public key used in JWS A.3 example", "Wrong key ID");
        assertEquals(ec.getKeyOperations(),                 EMPTY_LIST,          "Wrong key operations");
        assertEquals(ec.getKeyType(),                       JWKKeyType.EC,       "Wrong key type");
        assertNull  (ec.getPublicKeyUse(),                                       "Wrong public key use");
        assertEquals(ec.getX509CertificateChain(),          EMPTY_LIST,          "Wrong certificate chain");
        assertNull  (ec.getX509CertificateThumbprint(),                          "Wrong certificate thumbprint");
        assertNull  (ec.getX509CertificateThumbprintSHA256(),                    "Wrong certificate thumbprint (sha256)");
        assertNull  (ec.getX509Url(),                                            "Wrong X509 URL");

        final BigInteger x = parseBigInteger("f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU");
        final BigInteger y = parseBigInteger("x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0");
        assertEquals(ec.getCurve(),                         ECCurve.P_256,       "Wrong EC Curve");
        assertEquals(ec.getXCoordinate(),                   x,                   "Wrong X coordinate");
        assertEquals(ec.getYCoordinate(),                   y,                   "Wrong Y coordinate");
    }
}
