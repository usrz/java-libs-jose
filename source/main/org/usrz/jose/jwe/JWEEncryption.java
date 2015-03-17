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
package org.usrz.jose.jwe;

import org.usrz.jose.shared.JOSEIdentifier;

/**
 * An enumeration of all known {@link JWE} encryption algorithms.
 */
public enum JWEEncryption implements JOSEIdentifier {

    /** AES using 128 bit CBC keys and HMAC SHA-256 operations. */
    A128CBC_HS256("A128CBC-HS256"),
    /** AES using 192 bit CBC keys and HMAC SHA-384 operations. */
    A192CBC_HS384("A192CBC-HS384"),
    /** AES using 256 bit CBC keys and HMAC SHA-512 operations. */
    A256CBC_HS512("A256CBC-HS512"),
    /** AES in Galois/Counter Mode using 128 bit keys. */
    A128GCM      ("A128GCM"),
    /** AES in Galois/Counter Mode using 192 bit keys. */
    A192GCM      ("A192GCM"),
    /** AES in Galois/Counter Mode using 256 bit keys. */
    A256GCM      ("A256GCM");

    /* ====================================================================== */

    private final String identifier;

    private JWEEncryption(String identifier) {
        this.identifier = identifier;
    }

    @Override
    public String joseName() {
        return identifier;
    }
}
