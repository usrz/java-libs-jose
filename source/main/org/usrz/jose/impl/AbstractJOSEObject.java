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
package org.usrz.jose.impl;

import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.List;

import org.usrz.jose.JOSEAlgorithm;
import org.usrz.jose.JOSEObject;
import org.usrz.jose.jackson.JOSEObjectDeserializer;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;

/**
 * An abstract implementation of the {@link JOSEObject} interface.
 */
@JsonDeserialize(using=JOSEObjectDeserializer.class)
public abstract class AbstractJOSEObject<ALGORITHM extends JOSEAlgorithm>
implements JOSEObject<ALGORITHM> {

    private final ALGORITHM algorithm;
    private final String keyId;
    private final URI x509Url;
    private final List<X509Certificate> x509CertificateChain;
    private final byte[] x509CertificateThumbprint;
    private final byte[] x509CertificateThumbprintSHA256;

    protected AbstractJOSEObject(final ALGORITHM algorithm,
                         final String keyId,
                         final URI x509Url,
                         final List<X509Certificate> x509CertificateChain,
                         final byte[] x509CertificateThumbprint,
                         final byte[] x509CertificateThumbprintSHA256) {
        this.algorithm = algorithm;
        this.keyId = keyId;
        this.x509Url = x509Url;
        this.x509CertificateChain = x509CertificateChain;
        this.x509CertificateThumbprint = x509CertificateThumbprint;
        this.x509CertificateThumbprintSHA256 = x509CertificateThumbprintSHA256;
    }

    /**
     * The "alg" (algorithm) member identifies the algorithm intended for
     * use with the JOSE object.
     */
    @Override
    @JsonProperty(ALGORITHM)
    public ALGORITHM getAlgorithm() {
        return algorithm;
    }

    /**
     * The "kid" (key ID) member is used to match a specific key.
     */
    @Override
    @JsonProperty(KEY_ID)
    public String getKeyId() {
        return keyId;
    }

    /**
     * The "x5u" (X.509 URL) member is a URI that refers to a resource for an
     * X.509 public key certificate or certificate chain.
     *
     * The identified resource MUST provide a representation of the certificate
     * or certificate chain that conforms to RFC 5280 in PEM encoded form.
     */
    @Override
    @JsonProperty(X509_URL)
    public URI getX509Url() {
        return x509Url;
    }

    /**
     * The "x5c" (X.509 Certificate Chain) member contains a chain of one or
     * more PKIX certificates.
     */
    @Override
    @JsonProperty(X509_CERTIFICATE_CHAIN)
    public List<X509Certificate> getX509CertificateChain() {
        return x509CertificateChain;
    }

    /**
     * The "x5t" (X.509 Certificate SHA-1 Thumbprint) member is the SHA-1
     * thumbprint (a.k.a. digest) of the DER encoding of an X.509 certificate.
     */
    @Override
    @JsonProperty(X509_CERTIFICATE_THUMBPRINT)
    public byte[] getX509CertificateThumbprint() {
        return x509CertificateThumbprint;
    }

    /**
     * The "x5t#S256" (X.509 Certificate SHA-256 Thumbprint) member is the
     * SHA-256 thumbprint (a.k.a. digest) of the DER encoding of an X.509
     * certificate.
     */
    @Override
    @JsonProperty(X509_CERTIFICATE_THUMBPRINT_SHA256)
    public byte[] getX509CertificateThumbprintSHA256() {
        return x509CertificateThumbprintSHA256;
    }

    /* ====================================================================== */

    /**
     * An abstract builder to construct {@link JOSEObject} instances.
     */
    public static abstract class Builder<ALGORITHM extends JOSEAlgorithm,
                                         OBJECT extends AbstractJOSEObject<ALGORITHM>,
                                         BUILDER extends Builder<ALGORITHM, OBJECT, BUILDER>> {

        @SuppressWarnings("unchecked")
        protected final BUILDER builder = (BUILDER) this;

        protected ALGORITHM algorithm;
        protected String keyId;
        protected URI x509Url;
        protected List<X509Certificate> x509CertificateChain;
        protected byte[] x509CertificateThumbprint;
        protected byte[] x509CertificateThumbprintSHA256;

        public abstract OBJECT build();

        /**
         * The "alg" (algorithm) member identifies the algorithm intended for
         * use with the JOSE object.
         */
        @JsonProperty(ALGORITHM)
        public BUILDER withAlgorithm(ALGORITHM algorithm) {
            this.algorithm = algorithm;
            return builder;
        }

        /**
         * The "kid" (key ID) member is used to match a specific key.
         */
        @JsonProperty(KEY_ID)
        public BUILDER withKeyId(String keyID) {
            this.keyId = keyID;
            return builder;
        }

        /**
         * The "x5u" (X.509 URL) member is a URI that refers to a resource for an
         * X.509 public key certificate or certificate chain.
         *
         * The identified resource MUST provide a representation of the certificate
         * or certificate chain that conforms to RFC 5280 in PEM encoded form.
         */
        @JsonProperty(X509_URL)
        public BUILDER withX509Url(URI x509Url) {
            this.x509Url = x509Url;
            return builder;
        }

        /**
         * The "x5c" (X.509 Certificate Chain) member contains a chain of one or
         * more PKIX certificates.
         */
        @JsonProperty(X509_CERTIFICATE_CHAIN)
        public BUILDER withX509CertificateChain(List<X509Certificate> x509CertificateChain) {
            this.x509CertificateChain = x509CertificateChain;
            return builder;
        }

        /**
         * The "x5t" (X.509 Certificate SHA-1 Thumbprint) member is the SHA-1
         * thumbprint (a.k.a. digest) of the DER encoding of an X.509 certificate.
         */
        @JsonProperty(X509_CERTIFICATE_THUMBPRINT)
        public BUILDER withX509CertificateThumbprint(byte[] x509CertificateThumbprint) {
            this.x509CertificateThumbprint = x509CertificateThumbprint;
            return builder;
        }

        /**
         * The "x5t#S256" (X.509 Certificate SHA-256 Thumbprint) member is the
         * SHA-256 thumbprint (a.k.a. digest) of the DER encoding of an X.509
         * certificate.
         */
        @JsonProperty(X509_CERTIFICATE_THUMBPRINT_SHA256)
        public BUILDER withX509CertificateThumbprintSHA256(byte[] x509CertificateThumbprintSHA256) {
            this.x509CertificateThumbprintSHA256 = x509CertificateThumbprintSHA256;
            return builder;
        }

    }
}
