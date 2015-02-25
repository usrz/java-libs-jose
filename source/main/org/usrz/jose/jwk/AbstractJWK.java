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
package org.usrz.jose.jwk;

import java.net.URI;
import java.security.Key;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.usrz.jose.JOSEAlgorithm;
import org.usrz.jose.impl.AbstractJOSEObject;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;

public abstract class AbstractJWK<KEY extends Key>
extends AbstractJOSEObject<JOSEAlgorithm>
implements JWK<KEY> {

    private final JWKKeyType keyType;
    private final JWKPublicKeyUse publicKeyUse;
    private final List<JWKKeyOperation> keyOperations;

    protected AbstractJWK(final JOSEAlgorithm algorithm,
                          final String keyId,
                          final URI x509Url,
                          final List<X509Certificate> x509CertificateChain,
                          final byte[] x509CertificateThumbprint,
                          final byte[] x509CertificateThumbprintSHA256,
                          final JWKKeyType keyType,
                          final JWKPublicKeyUse publicKeyUse,
                          final List<JWKKeyOperation> keyOperations) {
        super(algorithm,
              keyId,
              x509Url,
              x509CertificateChain,
              x509CertificateThumbprint,
              x509CertificateThumbprintSHA256);
        this.keyType = keyType;
        this.publicKeyUse = publicKeyUse;
        this.keyOperations = keyOperations;
    }

    /**
     * The "kty" (key type) member identifies the cryptographic algorithm
     * family used with the key.
     */
    @Override
    @JsonProperty(KEY_TYPE)
    public JWKKeyType getKeyType() {
        return keyType;
    }

    /**
     * The "use" (public key use) member identifies the intended use of the
     * public key.
     */
    @Override
    @JsonProperty(PUBLIC_KEY_USE)
    public JWKPublicKeyUse getPublicKeyUse() {
        return publicKeyUse;
    }

    /**
     * The "key_ops" (key operations) member identifies the operation(s)
     * that the key is intended to be used for.
     */
    @Override
    @JsonProperty(KEY_OPERATIONS)
    public List<JWKKeyOperation> getKeyOperations() {
        return keyOperations;
    }

    public static abstract class Builder<KEY extends Key,
                                         JWKTYPE extends AbstractJWK<KEY>,
                                         BUILDER extends Builder<KEY, JWKTYPE, BUILDER>>
    extends AbstractJOSEObject.Builder<JOSEAlgorithm, JWKTYPE, BUILDER> {

        protected JWKKeyType keyType;
        protected JWKPublicKeyUse publicKeyUse;
        protected List<JWKKeyOperation> keyOperations = new ArrayList<>();

        /**
         * The "kty" (key type) member identifies the cryptographic algorithm
         * family used with the key.
         */
        @JsonProperty(KEY_TYPE)
        public BUILDER withKeyType(JWKKeyType keyType) {
            this.keyType = keyType;
            return builder;
        }

        /**
         * The "use" (public key use) member identifies the intended use of the
         * public key.
         */
        @JsonProperty(PUBLIC_KEY_USE)
        public BUILDER withPublicKeyUse(JWKPublicKeyUse publicKeyUse) {
            this.publicKeyUse = publicKeyUse;
            return builder;
        }

        /**
         * The "key_ops" (key operations) member identifies the operation(s)
         * that the key is intended to be used for.
         */
        @JsonIgnore
        public BUILDER getKeyOperation(JWKKeyOperation keyOperation) {
            this.keyOperations.add(keyOperation);
            return builder;
        }

        /**
         * The "key_ops" (key operations) member identifies the operation(s)
         * that the key is intended to be used for.
         */
        @JsonProperty(KEY_OPERATIONS)
        public BUILDER getKeyOperations(List<JWKKeyOperation> keyOperations) {
            this.keyOperations.addAll(keyOperations);
            return builder;
        }
    }
}
