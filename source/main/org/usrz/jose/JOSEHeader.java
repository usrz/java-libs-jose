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
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.ws.rs.core.MediaType;

import org.usrz.jose.jwk.JWK;

import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;

public abstract class JOSEHeader<A extends JOSEAlgorithm> extends JOSEObject<A> {

    private final URI jwkSetURL;
    private final JWK jwk;
    private final MediaType type;
    private final MediaType contentType;
    private final List<String> criticalExtensions;
    private final Map<String, Object> additionalHeaders;

    protected JOSEHeader(final A algorithm,
                         final String keyID,
                         final URI x509URI,
                         final List<X509Certificate> x509CertificateChain,
                         final byte[] x509CertificateThumbprint,
                         final byte[] x509CertificateThumbprintSHA256,
                         final URI jwkSetURL,
                         final JWK jwk,
                         final MediaType type,
                         final MediaType contentType,
                         final List<String> criticalExtensions,
                         final Map<String, Object> additionalHeaders) {
        super(algorithm,
              keyID,
              x509URI,
              x509CertificateChain,
              x509CertificateThumbprint,
              x509CertificateThumbprintSHA256);
        this.jwkSetURL = jwkSetURL;
        this.jwk = jwk;
        this.type = type;
        this.contentType = contentType;
        this.criticalExtensions = criticalExtensions;
        this.additionalHeaders = additionalHeaders;
    }

    /**
     * The "jku" (JWK Set URL) Header Parameter is a URI that
     * refers to a resource for a set of JSON-encoded public keys, one of
     * which corresponds to the key used to digitally sign the JWS, or
     * the public key to which the JWE was encrypted
     */
    @JsonProperty("jku")
    public URI getJWKSetURL() {
        return this.jwkSetURL;
    }

    /**
     * The "jwk" (JSON Web Key) Header Parameter is the public key that
     * corresponds to the key used to digitally sign the JWS, or the public
     * key to which the JWE was encrypted
     */
    @JsonProperty("jwk")
    public JWK getJWK() {
        return this.jwk;
    }

    /**
     * The "typ" (type) Header Parameter is used to declare the MIME Media
     * Type of this complete JWS or JWE.
     */
    @JsonProperty("typ")
    public MediaType getType() {
        return this.type;
    }

    /**
     * The "cty" (content type) Header Parameter is used to declare the MIME
     * Media Type of the secured content (the payload).
     */
    @JsonProperty("cty")
    public MediaType getContentType() {
        return this.contentType;
    }

    /**
     * The "crit" (critical) Header Parameter indicates that extensions to
     * the initial RFC versions of the JWS or JWE specification are being
     * used that MUST be understood and processed.
     */
    @JsonProperty("crit")
    public final List<String> getCriticalExtensions() {
        return this.criticalExtensions;
    }

    /**
     * Return additional headers found in this JWS or JEW header.
     */
    @JsonAnyGetter
    public Map<String, Object> getAdditionalHeaders() {
        return this.additionalHeaders;
    }

    /* ====================================================================== */

    public static abstract class Builder<A extends JOSEAlgorithm,
                                         H extends JOSEHeader<A>,
                                         B extends Builder<A, H, B>>
    extends JOSEObject.Builder<A, H, B> {

        protected URI jwkSetURL;
        protected JWK jwk;
        protected MediaType type;
        protected MediaType contentType;

        protected List<String> criticalExtensions = new ArrayList<>();
        protected Map<String, Object> additionalHeaders = new HashMap<>();

        /**
         * The "jku" (JWK Set URL) Header Parameter is a URI that
         * refers to a resource for a set of JSON-encoded public keys, one of
         * which corresponds to the key used to digitally sign the JWS, or
         * the public key to which the JWE was encrypted
         */
        @JsonProperty("jku")
        public B withJWKSetURL(URI jwkSetURL) {
            this.jwkSetURL = jwkSetURL;
            return builder;
        }

        /**
         * The "jwk" (JSON Web Key) Header Parameter is the public key that
         * corresponds to the key used to digitally sign the JWS, or the public
         * key to which the JWE was encrypted
         */
        @JsonProperty("jwk")
        public B withJWK(JWK jwk) {
            this.jwk = jwk;
            return builder;
        }

        /**
         * The "typ" (type) Header Parameter is used to declare the MIME Media
         * Type of this complete JWS or JWE.
         */
        @JsonProperty("typ")
        public B withType(MediaType type) {
            this.type = type;
            return builder;
        }

        /**
         * The "cty" (content type) Header Parameter is used to declare the MIME
         * Media Type of the secured content (the payload).
         */
        @JsonProperty("cty")
        public B withContentType(MediaType contentType) {
            this.contentType = contentType;
            return builder;
        }

        /**
         * The "crit" (critical) Header Parameter indicates that extensions to
         * the initial RFC versions of the JWS or JWE specification are being
         * used that MUST be understood and processed.
         */
        @JsonIgnore
        public B withCriticalExtension(String criticalExtension) {
            this.criticalExtensions.add(criticalExtension);
            return builder;
        }

        /**
         * The "crit" (critical) Header Parameter indicates that extensions to
         * the initial RFC versions of the JWS or JWE specification are being
         * used that MUST be understood and processed.
         */
        @JsonProperty("crit")
        public B withCriticalExtensions(List<String> criticalExtensions) {
            this.criticalExtensions.addAll(criticalExtensions);
            return builder;
        }

        /**
         * Additional headers found in this JWS or JEW header.
         */
        @JsonAnySetter
        public B withAdditionalHeaders(String name, Object value) {
            this.additionalHeaders.put(name, value);
            return builder;
        }

        /**
         * Return additional headers found in this JWS or JEW header.
         */
        @JsonIgnore
        public B withAdditionalHeaders(Map<String, Object> additionalHeaders) {
            this.additionalHeaders.putAll(additionalHeaders);
            return builder;
        }
    }
}
