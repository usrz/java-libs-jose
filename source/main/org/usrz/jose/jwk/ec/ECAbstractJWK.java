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
import java.security.Key;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECKey;
import java.util.List;

import org.usrz.jose.JOSEAlgorithm;
import org.usrz.jose.jwk.AbstractJWK;
import org.usrz.jose.jwk.JWKKeyOperation;
import org.usrz.jose.jwk.JWKKeyType;
import org.usrz.jose.jwk.JWKPublicKeyUse;
import org.usrz.jose.jwk.AbstractJWK.Builder;

import com.fasterxml.jackson.annotation.JsonProperty;

public abstract class ECAbstractJWK<KEY extends Key & ECKey>
extends AbstractJWK<KEY> {

    public static final String CURVE = "crv";
    public static final String X_COORDINATE = "x";
    public static final String Y_COORDINATE = "y";

    private final ECCurve curve;
    private final BigInteger x;
    private final BigInteger y;

    protected ECAbstractJWK(JOSEAlgorithm algorithm,
                            String keyId,
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
              keyId,
              x509url,
              x509CertificateChain,
              x509CertificateThumbprint,
              x509CertificateThumbprintSHA256,
              keyType,
              publicKeyUse, keyOperations);
        this.curve = curve;
        this.x = x;
        this.y = y;
    }

    /**
     * The "crv" (curve) member identifies the cryptographic curve used with
     * the key.
     */
    @JsonProperty(CURVE)
    public ECCurve getCurve() {
        return curve;
    }

    /**
     * The "x" (x coordinate) member contains the x coordinate for the
     * elliptic curve point.
     */
    @JsonProperty(X_COORDINATE)
    public BigInteger getXCoordinate() {
        return x;
    }

    /**
     * The "y" (y coordinate) member contains the y coordinate for the
     * elliptic curve point.
     */
    @JsonProperty(Y_COORDINATE)
    public BigInteger getYCoordinate() {
        return y;
    }

    public static abstract class Builder<KEY extends Key & ECKey,
                                         JWKTYPE extends ECAbstractJWK<KEY>,
                                         BUILDER extends Builder<KEY, JWKTYPE, BUILDER>>
    extends AbstractJWK.Builder<KEY, JWKTYPE, BUILDER> {

        protected ECCurve curve;
        protected BigInteger x;
        protected BigInteger y;

        /**
         * The "crv" (curve) member identifies the cryptographic curve used with
         * the key.
         */
        @JsonProperty(CURVE)
        public BUILDER getCurve(ECCurve curve) {
            this.curve = curve;
            return builder;
        }

        /**
         * The "x" (x coordinate) member contains the x coordinate for the
         * elliptic curve point.
         */
        @JsonProperty(X_COORDINATE)
        public BUILDER getXCoordinate(BigInteger x) {
            this.x = x;
            return builder;
        }

        /**
         * The "y" (y coordinate) member contains the y coordinate for the
         * elliptic curve point.
         */
        @JsonProperty(Y_COORDINATE)
        public BUILDER getYCoordinate(BigInteger y) {
            this.y = y;
            return builder;
        }

    }

}
