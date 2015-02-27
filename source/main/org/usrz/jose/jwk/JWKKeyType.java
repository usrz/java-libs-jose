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

import org.usrz.jose.core.Identifier;

/**
 * The "kty" (key type) member identifies the cryptographic algorithm
 * family used with the key, such as "RSA" or "EC".
 *
 * @author <a href="mailto:pier@usrz.com">Pier Fumagalli</a>
 */
public enum JWKKeyType implements Identifier {

    /** Elliptic Curve */
    EC("EC"),
    /** RSA */
    RSA("RSA"),
    /** Octet sequence (used to represent symmetric keys) */
    OCT("oct");

    /* ====================================================================== */

    private final String identifier;

    private JWKKeyType(String identifier) {
        this.identifier = identifier;
    }

    @Override
    public String joseId() {
        return identifier;
    }
}
