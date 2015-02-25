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
import java.security.interfaces.ECPrivateKey;
import java.util.List;

import org.usrz.jose.JOSEAlgorithm;
import org.usrz.jose.jwk.JWKKeyOperation;
import org.usrz.jose.jwk.JWKKeyType;
import org.usrz.jose.jwk.JWKPublicKeyUse;
import org.usrz.jose.jwk.PrivateJWK;

import com.fasterxml.jackson.annotation.JsonProperty;

public class ECPrivateJWK
extends ECAbstractJWK<ECPrivateKey>
implements PrivateJWK<ECPrivateKey> {

    public static final String ECC_PRIVATE_KEY = "d";

    private final BigInteger d;

    protected ECPrivateJWK(JOSEAlgorithm algorithm,
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
                           BigInteger y,
                           BigInteger d) {
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
        this.d = d;
    }

    /**
     * The "d" (ECC private key) member contains the Elliptic Curve private
     * key value.
     */
    @JsonProperty(ECC_PRIVATE_KEY)
    public BigInteger getECCPrivateKey() {
        return d;
    }


    public static class Builder
    extends ECAbstractJWK.Builder<ECPrivateKey, ECPrivateJWK, ECPrivateJWK.Builder> {

        private BigInteger d;

        @Override
        public ECPrivateJWK build() {
            return new ECPrivateJWK(algorithm,
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
                                    y,
                                    d);
        }

        /**
         * The "d" (ECC private key) member contains the Elliptic Curve private
         * key value.
         */
        @JsonProperty(ECC_PRIVATE_KEY)
        public Builder getECCPrivateKey(BigInteger d) {
            this.d = d;
            return builder;
        }
    }
}
