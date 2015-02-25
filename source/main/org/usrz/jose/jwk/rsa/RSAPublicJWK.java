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
package org.usrz.jose.jwk.rsa;

import java.math.BigInteger;
import java.net.URI;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.List;

import org.usrz.jose.JOSEAlgorithm;
import org.usrz.jose.jwk.JWKKeyOperation;
import org.usrz.jose.jwk.JWKKeyType;
import org.usrz.jose.jwk.JWKPublicKeyUse;
import org.usrz.jose.jwk.PublicJWK;

public class RSAPublicJWK
extends RSAAbstractJWK<RSAPublicKey>
implements PublicJWK<RSAPublicKey> {

    protected RSAPublicJWK(JOSEAlgorithm algorithm,
                           String keyID,
                           URI x509uri,
                           List<X509Certificate> x509CertificateChain,
                           byte[] x509CertificateThumbprint,
                           byte[] x509CertificateThumbprintSHA256,
                           JWKKeyType keyType,
                           JWKPublicKeyUse publicKeyUse,
                           List<JWKKeyOperation> keyOperations,
                           BigInteger n,
                           BigInteger e) {
        super(algorithm,
              keyID,
              x509uri,
              x509CertificateChain,
              x509CertificateThumbprint,
              x509CertificateThumbprintSHA256,
              keyType,
              publicKeyUse,
              keyOperations,
              n,
              e);
    }

    public static class Builder
    extends RSAAbstractJWK.Builder<RSAPublicKey, RSAPublicJWK, RSAPublicJWK.Builder> {

        @Override
        public RSAPublicJWK build() {
            return new RSAPublicJWK(algorithm,
                                    keyId,
                                    x509Url,
                                    x509CertificateChain,
                                    x509CertificateThumbprint,
                                    x509CertificateThumbprintSHA256,
                                    keyType,
                                    publicKeyUse,
                                    keyOperations,
                                    n,
                                    e);
        }
    }
}
