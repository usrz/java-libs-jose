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

import java.math.BigInteger;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

import com.fasterxml.jackson.annotation.JsonProperty;

@RequiredArgsConstructor
public class RSAPublicJWK extends JWK {

    /**
     * The "n" (modulus) member contains the modulus value for the RSA
     * public key.
     */
    //@JsonProperty("n")
    @Getter(onMethod=@__({@JsonProperty("n")}))
    private BigInteger modulus;

    /**
     * The "e" (exponent) member contains the exponent value for the RSA
     * public key.
     */
    //@JsonProperty("e")
    @Getter(onMethod=@__({@JsonProperty("e")}))
    private BigInteger publicExponent;

}
