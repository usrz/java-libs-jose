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
package org.usrz.jose.backup;

import java.math.BigInteger;

import com.fasterxml.jackson.annotation.JsonProperty;

public interface RSAPrivateJWK extends RSAPublicJWK {

    /**
     * The "d" (private exponent) member contains the private exponent value
     * for the RSA private key.
     */
    @JsonProperty("d")
    public BigInteger getPrivateExponent();

    /**
     * The "p" (first prime factor) member contains the first prime factor.
     */
    @JsonProperty("p")
    public BigInteger getPrimeP();

    /**
     * The "q" (second prime factor) member contains the second prime factor..
     */
    @JsonProperty("q")
    public BigInteger getPrimeQ();

    /**
     * The "dp" (first factor CRT exponent) member contains the Chinese
     * Remainder Theorem (CRT) exponent of the first factor.
     */
    @JsonProperty("dp")
    public BigInteger getPrimeExponentP();

    /**
     * The "dq" (second factor CRT exponent) member contains the Chinese
     * Remainder Theorem (CRT) exponent of the second factor.
     */
    @JsonProperty("dq")
    public BigInteger getPrimeExponentQ();

    /**
     * The "qi" (first CRT coefficient) member contains the Chinese
     * Remainder Theorem (CRT) coefficient of the second factor.
     */
    @JsonProperty("qi")
    public BigInteger getCrtCoefficient();

}
