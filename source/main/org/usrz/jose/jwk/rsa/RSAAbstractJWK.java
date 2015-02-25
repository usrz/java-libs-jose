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
package org.usrz.jose.jwk.rsa;

import java.math.BigInteger;
import java.net.URI;
import java.security.Key;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAKey;
import java.util.List;

import org.usrz.jose.JOSEAlgorithm;
import org.usrz.jose.jwk.AbstractJWK;
import org.usrz.jose.jwk.JWKKeyOperation;
import org.usrz.jose.jwk.JWKKeyType;
import org.usrz.jose.jwk.JWKPublicKeyUse;

import com.fasterxml.jackson.annotation.JsonProperty;

public abstract class RSAAbstractJWK<KEY extends Key & RSAKey>
extends AbstractJWK<KEY> {

    public static final String MODULUS = "n";
    public static final String PUBLIC_EXPONENT = "e";

    private final BigInteger n;
    private final BigInteger e;

    protected RSAAbstractJWK(JOSEAlgorithm algorithm,
                             String keyID,
                             URI x509uri,
                             List<X509Certificate> x509CertificateChain,
                             byte[] x509CertificateThumbprint,
                             byte[] x509CertificateThumbprintSHA256,
                             JWKKeyType keyType,
                             JWKPublicKeyUse publicKeyUse,
                             List<JWKKeyOperation> keyOperations,
                             BigInteger n,
                             BigInteger e) {
        super(algorithm,
              keyID,
              x509uri,
              x509CertificateChain,
              x509CertificateThumbprint,
              x509CertificateThumbprintSHA256,
              keyType,
              publicKeyUse,
              keyOperations);
        this.n = n;
        this.e = e;
    }

    /**
     * The "n" (modulus) member contains the modulus value for the RSA
     * public key.
     */
    @JsonProperty(MODULUS)
    public BigInteger getModulus() {
        return n;
    }

    /**
     * The "e" (exponent) member contains the public exponent value for
     * the RSA key.
     */
    @JsonProperty(PUBLIC_EXPONENT)
    public BigInteger getPublicExponent() {
        return e;
    }

    public static abstract class Builder<KEY extends Key & RSAKey,
                                         JWKTYPE extends RSAAbstractJWK<KEY>,
                                         BUILDER extends Builder<KEY, JWKTYPE, BUILDER>>
    extends AbstractJWK.Builder<KEY, JWKTYPE, BUILDER> {

        protected BigInteger n;
        protected BigInteger e;

        /**
         * The "n" (modulus) member contains the modulus value for the RSA
         * public key.
         */
        @JsonProperty(MODULUS)
        public BUILDER getModulus(BigInteger n) {
            this.n = n;
            return builder;
        }

        /**
         * The "e" (exponent) member contains the public exponent value for
         * the RSA key.
         */
        @JsonProperty(PUBLIC_EXPONENT)
        public BUILDER getPublicExponent(BigInteger e) {
            this.e = e;
            return builder;
        }
    }
}
