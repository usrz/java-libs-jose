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
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.List;

import org.usrz.jose.JOSEAlgorithm;
import org.usrz.jose.jwk.JWKKeyOperation;
import org.usrz.jose.jwk.JWKKeyType;
import org.usrz.jose.jwk.JWKPublicKeyUse;
import org.usrz.jose.jwk.PrivateJWK;

import com.fasterxml.jackson.annotation.JsonProperty;

public class RSAPrivateJWK
extends RSAAbstractJWK<RSAPrivateKey>
implements PrivateJWK<RSAPrivateKey> {

    public static final String PRIVATE_EXPONENT = "d";
    public static final String PRIME_P = "p";
    public static final String PRIME_Q = "q";
    public static final String PRIME_EXPONENT_P = "dp";
    public static final String PRIME_EXPONENT_Q = "dq";
    public static final String CRT_COEFFICIENT = "qi";

    private final BigInteger d;
    private final BigInteger p;
    private final BigInteger q;
    private final BigInteger dp;
    private final BigInteger dq;
    private final BigInteger qi;

    protected RSAPrivateJWK(JOSEAlgorithm algorithm,
                            String keyID,
                            URI x509uri,
                            List<X509Certificate> x509CertificateChain,
                            byte[] x509CertificateThumbprint,
                            byte[] x509CertificateThumbprintSHA256,
                            JWKKeyType keyType,
                            JWKPublicKeyUse publicKeyUse,
                            List<JWKKeyOperation> keyOperations,
                            BigInteger n,
                            BigInteger e,
                            BigInteger d,
                            BigInteger p,
                            BigInteger q,
                            BigInteger dp,
                            BigInteger dq,
                            BigInteger qi) {
        super(algorithm,
              keyID,
              x509uri,
              x509CertificateChain,
              x509CertificateThumbprint,
              x509CertificateThumbprintSHA256,
              keyType,
              publicKeyUse,
              keyOperations,
              n,
              e);
        this.d = d;
        this.p = p;
        this.q = q;
        this.dp = dp;
        this.dq = dq;
        this.qi = qi;
    }

    /**
     * The "d" (private exponent) member contains the private exponent value
     * for the RSA private key.
     */
    @JsonProperty(PRIVATE_EXPONENT)
    public BigInteger getPrivateExponent() {
        return d;
    }

    /**
     * The "p" (first prime factor) member contains the first prime factor
     * for the RSA private key.
     */
    @JsonProperty(PRIME_P)
    public BigInteger getPrimeP() {
        return p;
    }

    /**
     * The "q" (second prime factor) member contains the second prime factor
     * for the RSA private key.
     */
    @JsonProperty(PRIME_Q)
    public BigInteger getPrimeQ() {
        return q;
    }

    /**
     * The "dp" (first factor CRT exponent) member contains the Chinese
     * Remainder Theorem (CRT) exponent of the first factor.
     */
    @JsonProperty(PRIME_EXPONENT_P)
    public BigInteger getPrimeExponentP() {
        return dp;
    }

    /**
     * The "dq" (second factor CRT exponent) member contains the Chinese
     * Remainder Theorem (CRT) exponent of the second factor.
     */
    @JsonProperty(PRIME_EXPONENT_Q)
    public BigInteger getPrimeExponentQ() {
        return dq;
    }

    /**
     * The "qi" (first CRT coefficient) member contains the Chinese
     * Remainder Theorem (CRT) coefficient of the second factor.
     */
    @JsonProperty(CRT_COEFFICIENT)
    public BigInteger getCrtCoefficient() {
        return qi;
    }

    public static class Builder
    extends RSAAbstractJWK.Builder<RSAPrivateKey, RSAPrivateJWK, RSAPrivateJWK.Builder> {

        protected BigInteger d;
        protected BigInteger p;
        protected BigInteger q;
        protected BigInteger dp;
        protected BigInteger dq;
        protected BigInteger qi;

        @Override
        public RSAPrivateJWK build() {
            return new RSAPrivateJWK(algorithm,
                                     keyId,
                                     x509Url,
                                     x509CertificateChain,
                                     x509CertificateThumbprint,
                                     x509CertificateThumbprintSHA256,
                                     keyType,
                                     publicKeyUse,
                                     keyOperations,
                                     n,
                                     e,
                                     d,
                                     p,
                                     q,
                                     dp,
                                     dq,
                                     qi);
        }

        /**
         * The "d" (private exponent) member contains the private exponent value
         * for the RSA private key.
         */
        @JsonProperty(PRIVATE_EXPONENT)
        public Builder withPrivateExponent(BigInteger d) {
            this.d = d;
            return builder;
        }

        /**
         * The "p" (first prime factor) member contains the first prime factor
         * for the RSA private key.
         */
        @JsonProperty(PRIME_P)
        public Builder withPrimeP(BigInteger p) {
            this.p = p;
            return builder;
        }

        /**
         * The "q" (second prime factor) member contains the second prime factor
         * for the RSA private key.
         */
        @JsonProperty(PRIME_Q)
        public Builder withPrimeQ(BigInteger q) {
            this.q = q;
            return builder;
        }

        /**
         * The "dp" (first factor CRT exponent) member contains the Chinese
         * Remainder Theorem (CRT) exponent of the first factor.
         */
        @JsonProperty(PRIME_EXPONENT_P)
        public Builder withPrimeExponentP(BigInteger dp) {
            this.dp = dp;
            return builder;
        }

        /**
         * The "dq" (second factor CRT exponent) member contains the Chinese
         * Remainder Theorem (CRT) exponent of the second factor.
         */
        @JsonProperty(PRIME_EXPONENT_Q)
        public Builder withPrimeExponentQ(BigInteger dq) {
            this.dq = dq;
            return builder;
        }

        /**
         * The "qi" (first CRT coefficient) member contains the Chinese
         * Remainder Theorem (CRT) coefficient of the second factor.
         */
        @JsonProperty(CRT_COEFFICIENT)
        public Builder withCrtCoefficient(BigInteger qi) {
            this.qi = qi;
            return builder;
        }
    }
}
