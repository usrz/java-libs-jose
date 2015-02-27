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

import java.security.Key;
import java.util.List;

import org.usrz.jose.JOSEAlgorithm;
import org.usrz.jose.core.Common;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * A JSON Web Key (JWK) is a JavaScript Object Notation (JSON) data
 * structure that represents a cryptographic key.
 *
 * @param <KEY> The Java {@link Key} type represented by this {@link JWK}
 */
public interface JWK<KEY extends Key> extends Common<JOSEAlgorithm> {

    /** The {@code key_ops} header field name. */
    public static final String KEY_OPERATIONS = "key_ops";
    /** The {@code kty} header field name. */
    public static final String KEY_TYPE = "kty";
    /** The {@code use} header field name. */
    public static final String PUBLIC_KEY_USE = "use";

    /**
     * The "kty" (key type) member identifies the cryptographic algorithm
     * family used with the key.
     */
    @JsonProperty(KEY_TYPE)
    public JWKKeyType getKeyType();

    /**
     * The "use" (public key use) member identifies the intended use of the
     * public key.
     */
    @JsonProperty(PUBLIC_KEY_USE)
    public JWKPublicKeyUse getPublicKeyUse();

    /**
     * The "key_ops" (key operations) member identifies the operation(s)
     * that the key is intended to be used for.
     */
    @JsonProperty(KEY_OPERATIONS)
    public List<JWKKeyOperation> getKeyOperations();

}
