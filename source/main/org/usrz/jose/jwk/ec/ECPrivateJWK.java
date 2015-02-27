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
package org.usrz.jose.jwk.ec;

import java.math.BigInteger;
import java.security.interfaces.ECPrivateKey;

import org.usrz.jose.jwk.JWK;
import org.usrz.jose.jwk.PrivateJWK;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Implementation of the {@link JWK} interface for Elliptic Curve Private Keys.
 */
public interface ECPrivateJWK
extends ECJWK<ECPrivateKey>, PrivateJWK<ECPrivateKey> {

    /** The {@code d} JWK <i>("{@code EC}")</i> field name. */
    public static final String ECC_PRIVATE_KEY = "d";

    /**
     * The "d" (ECC private key) member contains the Elliptic Curve private
     * key value.
     */
    @JsonProperty(ECC_PRIVATE_KEY)
    public BigInteger getECCPrivateKey();

}
