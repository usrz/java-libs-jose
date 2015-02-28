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

import lombok.Data;
import lombok.Setter;
import lombok.experimental.Accessors;

import org.usrz.jose.core.Bytes;
import org.usrz.jose.jwk.JWK;
import org.usrz.jose.jwk.JWKKeyOperation;
import org.usrz.jose.jwk.JWKKeyType;
import org.usrz.jose.jwk.JWKPublicKeyUse;
import org.usrz.jose.jwk.PrivateJWK;
import org.usrz.jose.jws.JWSAlgorithm;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;

/**
 * Implementation of the {@link JWK} interface for Elliptic Curve Private Keys.
 */
@JsonDeserialize(builder=ECPrivateJWK.Builder.class)
public interface ECPrivateJWK
extends ECJWK<ECPrivateKey>, PrivateJWK<ECPrivateKey> {

    /** The {@code d} JWK <i>("{@code EC}")</i> field name. */
    public static final String ECC_PRIVATE_KEY = "d";

    /**
     * The "d" (ECC private key) member contains the Elliptic Curve private
     * key value.
     */
    @JsonProperty(ECC_PRIVATE_KEY)
    public BigInteger getEccPrivateKey();

    /* ====================================================================== */

    @Accessors(chain=true)
    @JsonPOJOBuilder(withPrefix="set")
    public static final class Builder
    extends ECJWK.Builder<ECPrivateKey, ECPrivateJWK, Builder> {

        public Builder() {
            super(Impl.class);
        }

        @Override
        public ECPrivateJWK build() {
            return super.build();
        }

        /* ================================================================== */

        /**
         * The "d" (ECC private key) member contains the Elliptic Curve private
         * key value.
         */
        @Setter(onMethod=@__({@JsonProperty(ECC_PRIVATE_KEY)}))
        private BigInteger eccPrivateKey;

        /* ================================================================== */

        @Data
        private static final class Impl implements ECPrivateJWK {

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
            private final BigInteger eccPrivateKey;
        }
    }
}
