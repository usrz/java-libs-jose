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
import java.security.Key;
import java.security.interfaces.RSAKey;

import lombok.Setter;
import lombok.experimental.Accessors;

import org.usrz.jose.jwk.JWK;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;

public interface RSAJWK<KEY extends Key & RSAKey>
extends JWK<KEY> {

    /** The {@code n} JWK <i>("{@code RSA}")</i> field name. */
    public static final String MODULUS = "n";
    /** The {@code e} JWK <i>("{@code RSA}")</i> field name. */
    public static final String PUBLIC_EXPONENT = "e";

    /**
     * The "n" (modulus) member contains the modulus value for the RSA
     * public key.
     */
    @JsonProperty(MODULUS)
    public BigInteger getModulus();

    /**
     * The "e" (exponent) member contains the public exponent value for
     * the RSA key.
     */
    @JsonProperty(PUBLIC_EXPONENT)
    public BigInteger getPublicExponent();

    /* ====================================================================== */

    @Accessors(chain=true)
    @JsonPOJOBuilder(withPrefix="set")
    public abstract static class Builder<K extends Key & RSAKey,
                                         J extends RSAJWK<K>,
                                         B extends Builder<K, J, B>>
    extends JWK.Builder<K, J, B> {

        protected Builder(Class<? extends J> type) {
            super(type);
        }

        /* ================================================================== */

        /**
         * The "n" (modulus) member contains the modulus value for the RSA
         * public key.
         */
        @Setter(onMethod=@__({@JsonProperty(MODULUS)}))
        private BigInteger modulus;

        /**
         * The "e" (exponent) member contains the public exponent value for
         * the RSA key.
         */
        @Setter(onMethod=@__({@JsonProperty(PUBLIC_EXPONENT)}))
        private BigInteger publicExponent;

    }
}