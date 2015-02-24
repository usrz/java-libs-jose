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

import org.usrz.jose.JOSEAlgorithm;
import org.usrz.jose.jwk.JWKKeyType;
import org.usrz.jose.jwk.JWKPublicKeyUse;

public enum JWEAlgorithm implements JOSEAlgorithm {

    RSA1_5                ("RSA1_5"),
    RSA_OAEP              ("RSA-OAEP"),
    RSA_OAEP_256          ("RSA-OAEP-256"),
    A128KW                ("A128KW"),
    A192KW                ("A192KW"),
    A256KW                ("A256KW"),
    DIR                   ("dir"),
    ECDH_ES               ("ECDH-ES"),
    ECDH_ESwithA128KW     ("ECDH-ES+A128KW"),
    ECDH_ESwithA192KW     ("ECDH-ES+A192KW"),
    ECDH_ESwithA256KW     ("ECDH-ES+A256KW"),
    A128GCMKW             ("A128GCMKW"),
    A192GCMKW             ("A192GCMKW"),
    A256GCMKW             ("A256GCMKW"),
    PBES2_HS256withA128KW ("PBES2-HS256+A128KW"),
    PBES2_HS384withA192KW ("PBES2-HS384+A192KW"),
    PBES2_HS512withA256KW ("PBES2-HS512+A256KW");

    /* ====================================================================== */

    private final String identifier;

    private JWEAlgorithm(String identifier) {
        this.identifier = identifier;
    }

    @Override
    public String getIdentifier() {
        return identifier;
    }

    @Override
    public JWKKeyType getKeyType() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public JWKPublicKeyUse getPublicKeyUse() {
        return JWKPublicKeyUse.ENC;
    }
}
