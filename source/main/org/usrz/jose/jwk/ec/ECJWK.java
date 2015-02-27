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
import java.security.Key;
import java.security.interfaces.ECKey;

import org.usrz.jose.jwk.JWK;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * An abstract implementation of the {@link JWK} interface for Elliptic Curves.
 */
public interface ECJWK<KEY extends Key & ECKey>
extends JWK<KEY> {

    /** The {@code crv} JWK <i>("{@code EC}")</i> field name. */
    public static final String CURVE = "crv";
    /** The {@code x} JWK <i>("{@code EC}")</i> field name. */
    public static final String X_COORDINATE = "x";
    /** The {@code y} JWK <i>("{@code EC}")</i> field name. */
    public static final String Y_COORDINATE = "y";

    /**
     * The "crv" (curve) member identifies the cryptographic curve used with
     * the key.
     */
    @JsonProperty(CURVE)
    public ECCurve getCurve();

    /**
     * The "x" (x coordinate) member contains the x coordinate for the
     * elliptic curve point.
     */
    @JsonProperty(X_COORDINATE)
    public BigInteger getXCoordinate();

    /**
     * The "y" (y coordinate) member contains the y coordinate for the
     * elliptic curve point.
     */
    @JsonProperty(Y_COORDINATE)
    public BigInteger getYCoordinate();

}
