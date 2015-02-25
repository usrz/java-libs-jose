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
package org.usrz.jose;

import org.usrz.jose.jwe.JWEHeader;
import org.usrz.jose.jwk.JWKKeyType;
import org.usrz.jose.jwk.JWKPublicKeyUse;
import org.usrz.jose.jws.JWSHeader;

/**
 * An interface abstracting a <i>JOSE</i> algorithm, normally used in
 * {@link JWSHeader} or {@link JWEHeader} structures.
 */
public interface JOSEAlgorithm extends JOSEIdentifier {

    /**
     * The key type ({@linkplain JWKKeyType#EC Elliptic Curve},
     * {@linkplain JWKKeyType#RSA RSA}, &hellip;) associated with this
     * algorithm .
     */
    public JWKKeyType getKeyType();

    /**
     * The crypto operation ({@linkplain JWKPublicKeyUse#SIG signature
     * generation and verification}, {@linkplain JWKPublicKeyUse#ENC encryption
     * and decryption}, &hellip;) associated with this algorithm.
     */
    // TODO: Is this the correct value to return???
    public JWKPublicKeyUse getPublicKeyUse();

}
