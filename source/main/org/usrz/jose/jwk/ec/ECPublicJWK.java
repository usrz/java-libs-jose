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
package org.usrz.jose.jwk.ec;

import java.math.BigInteger;
import java.net.URI;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.List;

import org.usrz.jose.JOSEAlgorithm;
import org.usrz.jose.jwk.JWKKeyOperation;
import org.usrz.jose.jwk.JWKKeyType;
import org.usrz.jose.jwk.JWKPublicKeyUse;
import org.usrz.jose.jwk.PublicJWK;

public class ECPublicJWK
extends ECAbstractJWK<ECPublicKey>
implements PublicJWK<ECPublicKey> {

    protected ECPublicJWK(JOSEAlgorithm algorithm,
                          String keyID,
                          URI x509url,
                          List<X509Certificate> x509CertificateChain,
                          byte[] x509CertificateThumbprint,
                          byte[] x509CertificateThumbprintSHA256,
                          JWKKeyType keyType,
                          JWKPublicKeyUse publicKeyUse,
                          List<JWKKeyOperation> keyOperations,
                          ECCurve curve,
                          BigInteger x,
                          BigInteger y) {
        super(algorithm,
              keyID,
              x509url,
              x509CertificateChain,
              x509CertificateThumbprint,
              x509CertificateThumbprintSHA256,
              keyType,
              publicKeyUse,
              keyOperations,
              curve,
              x,
              y);
    }

    public static class Builder
    extends ECAbstractJWK.Builder<ECPublicKey, ECPublicJWK, ECPublicJWK.Builder> {

        @Override
        public ECPublicJWK build() {
            return new ECPublicJWK(algorithm,
                                   keyId,
                                   x509Url,
                                   x509CertificateChain,
                                   x509CertificateThumbprint,
                                   x509CertificateThumbprintSHA256,
                                   keyType,
                                   publicKeyUse,
                                   keyOperations,
                                   curve,
                                   x,
                                   y);
        }
    }
}
