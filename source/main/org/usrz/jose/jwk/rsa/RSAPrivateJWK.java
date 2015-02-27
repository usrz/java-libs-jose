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
import java.security.interfaces.RSAPrivateKey;

import org.usrz.jose.jwk.PrivateJWK;

import com.fasterxml.jackson.annotation.JsonProperty;

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

}
