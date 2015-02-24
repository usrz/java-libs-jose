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
package org.usrz.jose.jws;

import static org.usrz.jose.jwk.JWKKeyType.EC;
import static org.usrz.jose.jwk.JWKKeyType.OCT;
import static org.usrz.jose.jwk.JWKKeyType.RSA;
import static org.usrz.jose.jwk.JWKPublicKeyUse.SIG;

import org.usrz.jose.JOSEAlgorithm;
import org.usrz.jose.jwk.JWKKeyType;
import org.usrz.jose.jwk.JWKPublicKeyUse;

public enum JWSAlgorithm implements JOSEAlgorithm {

    /** HMAC using SHA-256 */
    HS256("HS256", OCT),
    /** HMAC using SHA-384 */
    HS384("HS384", OCT),
    /** HMAC using SHA-512 */
    HS512("HS512", OCT),

    /** RSASSA-PKCS-v1_5 using SHA-256 */
    RS256("RS256", RSA),
    /** RSASSA-PKCS-v1_5 using SHA-384 */
    RS384("RS384", RSA),
    /** RSASSA-PKCS-v1_5 using SHA-512 */
    RS512("RS512", RSA),

    /** ECDSA using P-256 and SHA-256 */
    ES256("ES256", EC),
    /** ECDSA using P-384 and SHA-2384 */
    ES384("ES384", EC),
    /** ECDSA using P-512 <i><small>(not 512)</small></i> and SHA-512 */
    ES512("ES512", EC),

    /** RSASSA-PSS using SHA-256 and MGF1 with SHA-256 */
    PS256("PS256", RSA),
    /** RSASSA-PSS using SHA-384 and MGF1 with SHA-384 */
    PS384("PS384", RSA),
    /** RSASSA-PSS using SHA-512 and MGF1 with SHA-512 */
    PS512("PS512", RSA),

    /** No digital signature or MAC performed */
    NONE ("none", null);

    /* ====================================================================== */

    private final String identifier;
    private final JWKKeyType keyType;

    private JWSAlgorithm(String identifier, JWKKeyType keyType) {
        this.identifier = identifier;
        this.keyType = keyType;
    }

    @Override
    public String getIdentifier() {
        return identifier;
    }

    @Override
    public JWKKeyType getKeyType() {
        return keyType;
    }

    @Override
    public JWKPublicKeyUse getPublicKeyUse() {
        return SIG;
    }
}
