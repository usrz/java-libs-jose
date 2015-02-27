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

import static org.usrz.jose.jwk.JWKKeyType.EC;
import static org.usrz.jose.jwk.JWKKeyType.OCT;
import static org.usrz.jose.jwk.JWKKeyType.RSA;

import org.usrz.jose.JOSEAlgorithm;
import org.usrz.jose.jwk.JWKKeyType;
import org.usrz.jose.jwk.JWKPublicKeyUse;

public enum JWEAlgorithm implements JOSEAlgorithm {

    DIR                   ("dir", null),
    /** RSAES-PKCS1-V1_5 */
    RSA1_5                ("RSA1_5", RSA),
    /** RSAES OAEP using default parameters */
    RSA_OAEP              ("RSA-OAEP", RSA),
    /** RSAES OAEP using SHA-256 and MGF1 with SHA-256 */
    RSA_OAEP_256          ("RSA-OAEP-256", RSA),
    /** AES Key Wrap with default initial value using 128 bit key */
    A128KW                ("A128KW", OCT),
    /** AES Key Wrap with default initial value using 192 bit key */
    A192KW                ("A192KW", OCT),
    /** AES Key Wrap with default initial value using 256 bit key */
    A256KW                ("A256KW", OCT),
    /** Elliptic Curve Diffie-Hellman Ephemeral Static key agreement using Concat KDF */
    ECDH_ES               ("ECDH-ES", EC),
    /** ECDH-ES using Concat KDF and CEK wrapped with "A128KW" */
    ECDH_ESwithA128KW     ("ECDH-ES+A128KW", EC),
    /** ECDH-ES using Concat KDF and CEK wrapped with "A192KW" */
    ECDH_ESwithA192KW     ("ECDH-ES+A192KW", EC),
    /** ECDH-ES using Concat KDF and CEK wrapped with "A256KW" */
    ECDH_ESwithA256KW     ("ECDH-ES+A256KW", EC),
    /** Key wrapping with AES GCM using 128 bit key */
    A128GCMKW             ("A128GCMKW", OCT),
    /** Key wrapping with AES GCM using 192 bit key */
    A192GCMKW             ("A192GCMKW", OCT),
    /** Key wrapping with AES GCM using 256 bit key */
    A256GCMKW             ("A256GCMKW", OCT),
    /** PBES2 with HMAC SHA-256 and "A128KW" wrapping */
    PBES2_HS256withA128KW ("PBES2-HS256+A128KW", OCT),
    /** PBES2 with HMAC SHA-384 and "A192KW" wrapping */
    PBES2_HS384withA192KW ("PBES2-HS384+A192KW", OCT),
    /** PBES2 with HMAC SHA-512 and "A256KW" wrapping */
    PBES2_HS512withA256KW ("PBES2-HS512+A256KW", OCT);

    /* ====================================================================== */

    private final String identifier;
    private final JWKKeyType keyType;

    private JWEAlgorithm(String identifier, JWKKeyType keyType) {
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
        return JWKPublicKeyUse.ENC;
    }
}
