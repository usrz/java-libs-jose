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
package org.usrz.jose.core;

import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import lombok.Setter;
import lombok.experimental.Accessors;

import org.usrz.jose.JOSEAlgorithm;
import org.usrz.jose.jwe.JWEAlgorithm;
import org.usrz.jose.jwe.JWEHeader;
import org.usrz.jose.jwk.JWK;
import org.usrz.jose.jws.JWSAlgorithm;
import org.usrz.jose.jws.JWSHeader;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;

/**
 * The {@link Common} interface defines all the properties common to
 * {@link JWSHeader}s, {@link JWEHeader}s and {@link JWK}s.
 *
 * @param <A> The type of the algorithm for this object, either a
 *            {@link JWSAlgorithm} or a {@link JWEAlgorithm}.
 */
public interface Common<A extends JOSEAlgorithm> {

    /** The {@code alg} field name. */
    public static final String ALGORITHM = "alg";
    /** The {@code kid} field name. */
    public static final String KEY_ID = "kid";
    /** The {@code x5c} field name. */
    public static final String X509_CERTIFICATE_CHAIN = "x5c";
    /** The {@code x5t} field name. */
    public static final String X509_CERTIFICATE_THUMBPRINT = "x5t";
    /** The {@code x5t#S256} field name. */
    public static final String X509_CERTIFICATE_THUMBPRINT_SHA256 = "x5t#S256";
    /** The {@code x5u} field name. */
    public static final String X509_URL = "x5u";

    /**
     * The "alg" (algorithm) member identifies the algorithm intended for
     * use with the JOSE object.
     */
    @JsonProperty(ALGORITHM)
    public A getAlgorithm();

    /**
     * The "kid" (key ID) member is used to match a specific key.
     */
    @JsonProperty(KEY_ID)
    public String getKeyId();

    /**
     * The "x5u" (X.509 URL) member is a URI that refers to a resource for an
     * X.509 public key certificate or certificate chain.
     *
     * The identified resource MUST provide a representation of the certificate
     * or certificate chain that conforms to RFC 5280 in PEM encoded form.
     */
    @JsonProperty(X509_URL)
    public URI getX509Url();

    /**
     * The "x5c" (X.509 Certificate Chain) member contains a chain of one or
     * more PKIX certificates.
     */
    @JsonProperty(X509_CERTIFICATE_CHAIN)
    public List<X509Certificate> getX509CertificateChain();

    /**
     * The "x5t" (X.509 Certificate SHA-1 Thumbprint) member is the SHA-1
     * thumbprint (a.k.a. digest) of the DER encoding of an X.509 certificate.
     */
    @JsonProperty(X509_CERTIFICATE_THUMBPRINT)
    public Bytes getX509CertificateThumbprint();

    /**
     * The "x5t#S256" (X.509 Certificate SHA-256 Thumbprint) member is the
     * SHA-256 thumbprint (a.k.a. digest) of the DER encoding of an X.509
     * certificate.
     */
    @JsonProperty(X509_CERTIFICATE_THUMBPRINT_SHA256)
    public Bytes getX509CertificateThumbprintSHA256();

    /* ====================================================================== */

    @Accessors(chain=true)
    @JsonPOJOBuilder(withPrefix="set")
    public abstract class Builder<A extends JOSEAlgorithm,
                                  C extends Common<A>,
                                  B extends Builder<A, C, B>>
    extends BeanBuilder<C> {

        @SuppressWarnings("unused")
        private final List<X509Certificate> x509CertificateChain;
        private final List<X509Certificate> x509CertificateChainList;

        protected Builder(Class<? extends C> type) {
            super(type);
            x509CertificateChainList = new ArrayList<>();
            x509CertificateChain = Collections.unmodifiableList(x509CertificateChainList);
        }

        /* ================================================================== */

        /**
         * The "alg" (algorithm) member identifies the algorithm intended for
         * use with the JOSE object.
         */
        @Setter(onMethod=@__({@JsonProperty(ALGORITHM)}))
        private A algorithm;

        /**
         * The "kid" (key ID) member is used to match a specific key.
         */
        @Setter(onMethod=@__({@JsonProperty(KEY_ID)}))
        private String keyId;

        /**
         * The "x5u" (X.509 URL) member is a URI that refers to a resource for an
         * X.509 public key certificate or certificate chain.
         *
         * The identified resource MUST provide a representation of the certificate
         * or certificate chain that conforms to RFC 5280 in PEM encoded form.
         */
        @Setter(onMethod=@__({@JsonProperty(X509_URL)}))
        private URI x509Url;

        /**
         * The "x5t" (X.509 Certificate SHA-1 Thumbprint) member is the SHA-1
         * thumbprint (a.k.a. digest) of the DER encoding of an X.509 certificate.
         */
        @Setter(onMethod=@__({@JsonProperty(X509_CERTIFICATE_THUMBPRINT)}))
        private Bytes x509CertificateThumbprint;

        /**
         * The "x5t#S256" (X.509 Certificate SHA-256 Thumbprint) member is the
         * SHA-256 thumbprint (a.k.a. digest) of the DER encoding of an X.509
         * certificate.
         */
        @Setter(onMethod=@__({@JsonProperty(X509_CERTIFICATE_THUMBPRINT_SHA256)}))
        private Bytes x509CertificateThumbprintSHA256;

        /* ================================================================== */

        /**
         * The "x5c" (X.509 Certificate Chain) member contains a chain of one or
         * more PKIX certificates.
         */
        @SuppressWarnings("unchecked")
        @JsonProperty(X509_CERTIFICATE_CHAIN)
        public B setX509CertificateChain(Iterable<X509Certificate> x509CertificateChain) {
            if (x509CertificateChain == null) return (B) this;
            x509CertificateChain.forEach((certificate) -> {
                x509CertificateChainList.add(certificate);
            });
            return (B) this;
        }

        /**
         * The "x5c" (X.509 Certificate Chain) member contains a chain of one or
         * more PKIX certificates.
         */
        @JsonIgnore
        @SuppressWarnings("unchecked")
        public B addX509CertificateChain(X509Certificate x509Certificate) {
            x509CertificateChainList.add(x509Certificate);
            return (B) this;
        }
    }
}
