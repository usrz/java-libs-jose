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

import static org.usrz.jose.jwk.AbstractJWK.KEY_OPERATIONS;
import static org.usrz.jose.jwk.AbstractJWK.KEY_TYPE;
import static org.usrz.jose.jwk.AbstractJWK.PUBLIC_KEY_USE;

import java.util.List;

import org.usrz.jose.JOSEAlgorithm;
import org.usrz.jose.JOSEObject;

import com.fasterxml.jackson.annotation.JsonProperty;

public interface JWK extends JOSEObject<JOSEAlgorithm> {

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
