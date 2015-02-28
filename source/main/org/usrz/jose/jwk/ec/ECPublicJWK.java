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

import lombok.Data;
import lombok.experimental.Accessors;

import org.usrz.jose.core.BeanBuilder;
import org.usrz.jose.core.Bytes;
import org.usrz.jose.jwk.JWK;
import org.usrz.jose.jwk.JWKKeyOperation;
import org.usrz.jose.jwk.JWKKeyType;
import org.usrz.jose.jwk.JWKPublicKeyUse;
import org.usrz.jose.jwk.PublicJWK;
import org.usrz.jose.jws.JWSAlgorithm;

import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;

/**
 * Implementation of the {@link JWK} interface for Elliptic Curve Public Keys.
 */
public interface ECPublicJWK
extends ECJWK<ECPublicKey>, PublicJWK<ECPublicKey> {

    /* ECPublicJWK is a simple marker interface */

    /* ====================================================================== */

    @Accessors(chain=true)
    @JsonPOJOBuilder(withPrefix="set")
    public static final class Builder
    extends ECJWK.Builder<ECPublicKey, ECPublicJWK, Builder> {

        private static final BeanBuilder<Builder, Impl> BUILDER = new BeanBuilder<>(Builder.class, Impl.class);

        @Override
        public ECPublicJWK build() {
            return BUILDER.build(this);
        }

        @Data
        private static final class Impl implements ECPublicJWK {

            /* Common */
            private final JWSAlgorithm algorithm;
            private final String keyId;
            private final URI x509Url;
            private final List<X509Certificate> x509CertificateChain;
            private final Bytes x509CertificateThumbprint;
            private final Bytes x509CertificateThumbprintSHA256;

            /* JWK */
            private final JWKKeyType keyType;
            private final JWKPublicKeyUse publicKeyUse;
            private final List<JWKKeyOperation> keyOperations;

            /* JWK "EC" */
            private final ECCurve curve;
            private final BigInteger xCoordinate;
            private final BigInteger yCoordinate;

        }
    }
}
