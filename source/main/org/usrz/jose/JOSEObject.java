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
package org.usrz.jose;

import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.List;

import org.usrz.jose.jackson.JOSEObjectDeserializer;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;

@JsonDeserialize(using=JOSEObjectDeserializer.class)
public abstract class JOSEObject<A extends JOSEAlgorithm> {

    private final A algorithm;
    private final String keyID;
    private final URI x509URI;
    private final List<X509Certificate> x509CertificateChain;
    private final byte[] x509CertificateThumbprint;
    private final byte[] x509CertificateThumbprintSHA256;

    protected JOSEObject(final A algorithm,
                         final String keyID,
                         final URI x509URI,
                         final List<X509Certificate> x509CertificateChain,
                         final byte[] x509CertificateThumbprint,
                         final byte[] x509CertificateThumbprintSHA256) {
        this.algorithm = algorithm;
        this.keyID = keyID;
        this.x509URI = x509URI;
        this.x509CertificateChain = x509CertificateChain;
        this.x509CertificateThumbprint = x509CertificateThumbprint;
        this.x509CertificateThumbprintSHA256 = x509CertificateThumbprintSHA256;
    }

    /**
     * The "alg" (algorithm) member identifies the algorithm intended for
     * use with the JOSE object.
     */
    @JsonProperty("alg")
    public A getAlgorithm() {
        return algorithm;
    }

    /**
     * The "kid" (key ID) member is used to match a specific key.
     */
    @JsonProperty("kid")
    public String getKeyID() {
        return keyID;
    }

    /**
     * The "x5u" (X.509 URL) member is a URI that refers to a resource for an
     * X.509 public key certificate or certificate chain.
     *
     * The identified resource MUST provide a representation of the certificate
     * or certificate chain that conforms to RFC 5280 in PEM encoded form.
     */
    @JsonProperty("x5u")
    public URI getX509URI() {
        return x509URI;
    }

    /**
     * The "x5c" (X.509 Certificate Chain) member contains a chain of one or
     * more PKIX certificates.
     */
    @JsonProperty("x5c")
    public List<X509Certificate> getX509CertificateChain() {
        return x509CertificateChain;
    }

    /**
     * The "x5t" (X.509 Certificate SHA-1 Thumbprint) member is the SHA-1
     * thumbprint (a.k.a. digest) of the DER encoding of an X.509 certificate.
     */
    @JsonProperty("x5t")
    public byte[] getX509CertificateThumbprint() {
        return x509CertificateThumbprint;
    }

    /**
     * The "x5t#S256" (X.509 Certificate SHA-256 Thumbprint) member is the
     * SHA-256 thumbprint (a.k.a. digest) of the DER encoding of an X.509
     * certificate.
     */
    @JsonProperty("x5t#S256")
    public byte[] getX509CertificateThumbprintSHA256() {
        return x509CertificateThumbprintSHA256;
    }

    /* ====================================================================== */

    public static abstract class Builder<A extends JOSEAlgorithm,
                                         O extends JOSEObject<A>,
                                         B extends Builder<A, O, B>> {

        @SuppressWarnings("unchecked")
        protected final B builder = (B) this;

        protected A algorithm;
        protected String keyID;
        protected URI x509URI;
        protected List<X509Certificate> x509CertificateChain;
        protected byte[] x509CertificateThumbprint;
        protected byte[] x509CertificateThumbprintSHA256;

        public abstract O build();

        /**
         * The "alg" (algorithm) member identifies the algorithm intended for
         * use with the JOSE object.
         */
        @JsonProperty("alg")
        public B withAlgorithm(A algorithm) {
            this.algorithm = algorithm;
            return builder;
        }

        /**
         * The "kid" (key ID) member is used to match a specific key.
         */
        @JsonProperty("kid")
        public B withKeyID(String keyID) {
            this.keyID = keyID;
            return builder;
        }

        /**
         * The "x5u" (X.509 URL) member is a URI that refers to a resource for an
         * X.509 public key certificate or certificate chain.
         *
         * The identified resource MUST provide a representation of the certificate
         * or certificate chain that conforms to RFC 5280 in PEM encoded form.
         */
        @JsonProperty("x5u")
        public B withX509URI(URI x509URI) {
            this.x509URI = x509URI;
            return builder;
        }

        /**
         * The "x5c" (X.509 Certificate Chain) member contains a chain of one or
         * more PKIX certificates.
         */
        @JsonProperty("x5c")
        public B withX509CertificateChain(List<X509Certificate> x509CertificateChain) {
            this.x509CertificateChain = x509CertificateChain;
            return builder;
        }

        /**
         * The "x5t" (X.509 Certificate SHA-1 Thumbprint) member is the SHA-1
         * thumbprint (a.k.a. digest) of the DER encoding of an X.509 certificate.
         */
        @JsonProperty("x5t")
        public B withX509CertificateThumbprint(byte[] x509CertificateThumbprint) {
            this.x509CertificateThumbprint = x509CertificateThumbprint;
            return builder;
        }

        /**
         * The "x5t#S256" (X.509 Certificate SHA-256 Thumbprint) member is the
         * SHA-256 thumbprint (a.k.a. digest) of the DER encoding of an X.509
         * certificate.
         */
        @JsonProperty("x5t#S256")
        public B withX509CertificateThumbprintSHA256(byte[] x509CertificateThumbprintSHA256) {
            this.x509CertificateThumbprintSHA256 = x509CertificateThumbprintSHA256;
            return builder;
        }

    }
}
