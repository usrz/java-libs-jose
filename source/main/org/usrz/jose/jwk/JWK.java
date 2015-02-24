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
import java.security.cert.X509Certificate;
import java.util.List;

import org.usrz.jose.JOSEIdentifier;
import org.usrz.jose.JOSEObject;

import com.fasterxml.jackson.annotation.JsonProperty;

public abstract class JWK extends JOSEObject {

    private final JWKKeyType keyType;
    private final JWKPublicKeyUse publicKeyUse;
    private final List<JWKKeyOperation> keyOperations;

    protected JWK(final JOSEIdentifier algorithm,
                  final String keyID,
                  final URI x509URI,
                  final List<X509Certificate> x509CertificateChain,
                  final byte[] x509CertificateThumbprint,
                  final byte[] x509CertificateThumbprintSHA256,
                  final JWKKeyType keyType,
                  final JWKPublicKeyUse publicKeyUse,
                  final List<JWKKeyOperation> keyOperations) {
        super(algorithm,
              keyID,
              x509URI,
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
    @JsonProperty("kty")
    public JWKKeyType getKeyType() {
        return keyType;
    }

    /**
     * The "use" (public key use) member identifies the intended use of the
     * public key.
     */
    @JsonProperty("use")
    public JWKPublicKeyUse getPublicKeyUse() {
        return publicKeyUse;
    }

    /**
     * The "key_ops" (key operations) member identifies the operation(s)
     * that the key is intended to be used for.
     */
    @JsonProperty("key_ops")
    public List<JWKKeyOperation> getKeyOperations() {
        return keyOperations;
    }
}
