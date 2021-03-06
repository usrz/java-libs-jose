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

import org.usrz.jose.shared.JOSEIdentifier;


/**
 * The "key_ops" (key operations) member identifies the operation(s)
 * that the key is intended to be used for.
 *
 * @author <a href="mailto:pier@usrz.com">Pier Fumagalli</a>
 */
public enum JWKKeyOperation implements JOSEIdentifier {

    /** Compute digital signature or MAC. */
    SIGN("sign"),
    /** Verify digital signature or MAC. */
    VERIFY("verify"),
    /** Encrypt content. */
    ENCRYPT("encrypt"),
    /** Decrypt content and validate decryption, if applicable. */
    DECRYPT("decrypt"),
    /** Encrypt key. */
    WRAP_KEY("wrapKey"),
    /** Decrypt key and validate decryption, if applicable. */
    UNWRAP_KEY("unwrapKey"),
    /** Derive key. */
    DERIVE_KEY("deriveKey"),
    /** Derive bits not to be used as a key. */
    DERIVE_BITS("deriveBits");

    private final String identifier;

    private JWKKeyOperation(String identifier) {
        this.identifier = identifier;
    }

    @Override
    public String joseName() {
        return identifier;
    }
}
