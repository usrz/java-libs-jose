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

import lombok.Data;
import lombok.Setter;
import lombok.experimental.Accessors;

import org.usrz.jose.core.Bytes;
import org.usrz.jose.jwk.JWKKeyOperation;
import org.usrz.jose.jwk.JWKKeyType;
import org.usrz.jose.jwk.JWKPublicKeyUse;
import org.usrz.jose.jwk.PrivateJWK;
import org.usrz.jose.jws.JWSAlgorithm;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;

@JsonDeserialize(builder=RSAPrivateJWK.Builder.class)
public interface RSAPrivateJWK
extends RSAJWK<RSAPrivateKey>, PrivateJWK<RSAPrivateKey> {

    /** The {@code d} JWK <i>("{@code RSA}")</i> field name. */
    public static final String PRIVATE_EXPONENT = "d";
    /** The {@code p} JWK <i>("{@code RSA}")</i> field name. */
    public static final String PRIME_P = "p";
    /** The {@code q} JWK <i>("{@code RSA}")</i> field name. */
    public static final String PRIME_Q = "q";
    /** The {@code dp} JWK <i>("{@code RSA}")</i> field name. */
    public static final String PRIME_EXPONENT_P = "dp";
    /** The {@code dq} JWK <i>("{@code RSA}")</i> field name. */
    public static final String PRIME_EXPONENT_Q = "dq";
    /** The {@code qi} JWK <i>("{@code RSA}")</i> field name. */
    public static final String CRT_COEFFICIENT = "qi";

    /**
     * The "d" (private exponent) member contains the private exponent value
     * for the RSA private key.
     */
    @JsonProperty(PRIVATE_EXPONENT)
    public BigInteger getPrivateExponent();

    /**
     * The "p" (first prime factor) member contains the first prime factor
     * for the RSA private key.
     */
    @JsonProperty(PRIME_P)
    public BigInteger getPrimeP();

    /**
     * The "q" (second prime factor) member contains the second prime factor
     * for the RSA private key.
     */
    @JsonProperty(PRIME_Q)
    public BigInteger getPrimeQ();

    /**
     * The "dp" (first factor CRT exponent) member contains the Chinese
     * Remainder Theorem (CRT) exponent of the first factor.
     */
    @JsonProperty(PRIME_EXPONENT_P)
    public BigInteger getPrimeExponentP();

    /**
     * The "dq" (second factor CRT exponent) member contains the Chinese
     * Remainder Theorem (CRT) exponent of the second factor.
     */
    @JsonProperty(PRIME_EXPONENT_Q)
    public BigInteger getPrimeExponentQ();

    /**
     * The "qi" (first CRT coefficient) member contains the Chinese
     * Remainder Theorem (CRT) coefficient of the second factor.
     */
    @JsonProperty(CRT_COEFFICIENT)
    public BigInteger getCrtCoefficient();

    /* ====================================================================== */

    @Accessors(chain=true)
    @JsonPOJOBuilder(withPrefix="set")
    public static final class Builder
    extends RSAJWK.Builder<RSAPrivateKey, RSAPrivateJWK, Builder> {

        public Builder() {
            super(Impl.class);
        }

        @Override
        public RSAPrivateJWK build() {
            return super.build();
        }

        /* ================================================================== */

        /**
         * The "d" (private exponent) member contains the private exponent value
         * for the RSA private key.
         */
        @Setter(onMethod=@__({@JsonProperty(PRIVATE_EXPONENT)}))
        private BigInteger privateExponent;

        /**
         * The "p" (first prime factor) member contains the first prime factor
         * for the RSA private key.
         */
        @Setter(onMethod=@__({@JsonProperty(PRIME_P)}))
        private BigInteger primeP;

        /**
         * The "q" (second prime factor) member contains the second prime factor
         * for the RSA private key.
         */
        @Setter(onMethod=@__({@JsonProperty(PRIME_Q)}))
        private BigInteger primeQ;


        /**
         * The "dp" (first factor CRT exponent) member contains the Chinese
         * Remainder Theorem (CRT) exponent of the first factor.
         */
        @Setter(onMethod=@__({@JsonProperty(PRIME_EXPONENT_P)}))
        private BigInteger primeExponentP;

        /**
         * The "dq" (second factor CRT exponent) member contains the Chinese
         * Remainder Theorem (CRT) exponent of the second factor.
         */
        @Setter(onMethod=@__({@JsonProperty(PRIME_EXPONENT_Q)}))
        private BigInteger primeExponentQ;

        /**
         * The "qi" (first CRT coefficient) member contains the Chinese
         * Remainder Theorem (CRT) coefficient of the second factor.
         */
        @Setter(onMethod=@__({@JsonProperty(CRT_COEFFICIENT)}))
        private BigInteger crtCoefficient;

        /* ================================================================== */

        @Data
        private static final class Impl implements RSAPrivateJWK {

            /* Common */
            private final JWSAlgorithm algorithm;
            private final String keyId;
            private final URI x509Url;
            private final List<X509Certificate> x509CertificateChain;
            private final Bytes x509CertificateThumbprint;
            private final Bytes x509CertificateThumbprintSHA256;

            /* JWK */
            private final JWKKeyType keyType;
            private final JWKPublicKeyUse publicKeyUse;
            private final List<JWKKeyOperation> keyOperations;

            /* JWK (RSA) */
            private final BigInteger modulus;
            private final BigInteger publicExponent;
            private final BigInteger privateExponent;
            private final BigInteger primeP;
            private final BigInteger primeQ;
            private final BigInteger primeExponentP;
            private final BigInteger primeExponentQ;
            private final BigInteger crtCoefficient;

        }
    }
}
