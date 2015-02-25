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
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.ws.rs.core.MediaType;

import org.usrz.jose.JOSEAlgorithm;
import org.usrz.jose.JOSEHeader;
import org.usrz.jose.jwk.JWK;

import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * An abstract implementation of the {@link JOSEHeader} interface.
 */
public abstract class AbstractJOSEHeader<ALGORITHM extends JOSEAlgorithm>
extends AbstractJOSEObject<ALGORITHM>
implements JOSEHeader<ALGORITHM> {

    private final URI jsonWebKeySetUrl;
    private final JWK<?> jsonWebKey;
    private final MediaType mediaType;
    private final MediaType contentMediaType;
    private final List<String> criticalExtensions;
    private final Map<String, Object> additionalHeaders;

    protected AbstractJOSEHeader(final ALGORITHM algorithm,
                         final String keyID,
                         final URI x509URI,
                         final List<X509Certificate> x509CertificateChain,
                         final byte[] x509CertificateThumbprint,
                         final byte[] x509CertificateThumbprintSHA256,
                         final URI jwkSetURL,
                         final JWK<?> jwk,
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
        this.jsonWebKeySetUrl = jwkSetURL;
        this.jsonWebKey = jwk;
        this.mediaType = type;
        this.contentMediaType = contentType;
        this.criticalExtensions = criticalExtensions;
        this.additionalHeaders = additionalHeaders;
    }

    /**
     * The "jku" (JWK Set URL) Header Parameter is a URI that
     * refers to a resource for a set of JSON-encoded public keys, one of
     * which corresponds to the key used to digitally sign the JWS, or
     * the public key to which the JWE was encrypted
     */
    @Override
    @JsonProperty(JSON_WEB_KEY_SET_URL)
    public URI getJsonWebKeySetUrl() {
        return this.jsonWebKeySetUrl;
    }

    /**
     * The "jwk" (JSON Web Key) Header Parameter is the public key that
     * corresponds to the key used to digitally sign the JWS, or the public
     * key to which the JWE was encrypted
     */
    @Override
    @JsonProperty(JSON_WEB_KEY)
    public JWK<?> getJsonWebKey() {
        return this.jsonWebKey;
    }

    /**
     * The "typ" (type) Header Parameter is used to declare the MIME Media
     * Type of this complete JWS or JWE.
     */
    @Override
    @JsonProperty(MEDIA_TYPE)
    public MediaType getMediaType() {
        return this.mediaType;
    }

    /**
     * The "cty" (content type) Header Parameter is used to declare the MIME
     * Media Type of the secured content (the payload).
     */
    @Override
    @JsonProperty(CONTENT_MEDIA_TYPE)
    public MediaType getContentMediaType() {
        return this.contentMediaType;
    }

    /**
     * The "crit" (critical) Header Parameter indicates that extensions to
     * the initial RFC versions of the JWS or JWE specification are being
     * used that MUST be understood and processed.
     */
    @Override
    @JsonProperty(CRITICAL_EXTENSIONS)
    public final List<String> getCriticalExtensions() {
        return this.criticalExtensions;
    }

    /**
     * Return additional headers found in this JWS or JEW header.
     */
    @Override
    @JsonAnyGetter
    public Map<String, Object> getAdditionalHeaders() {
        return this.additionalHeaders;
    }

    /* ====================================================================== */

    /**
     * An abstract builder to construct {@link JOSEHeader} instances.
     */
    public static abstract class Builder<ALGORITHM extends JOSEAlgorithm,
                                         HEADER extends AbstractJOSEHeader<ALGORITHM>,
                                         BUILDER extends Builder<ALGORITHM, HEADER, BUILDER>>
    extends AbstractJOSEObject.Builder<ALGORITHM, HEADER, BUILDER> {

        protected URI jsonWebKeySetUrl;
        protected JWK<?> jsonWebKey;
        protected MediaType mediaType;
        protected MediaType contentMediaType;

        protected List<String> criticalExtensions = new ArrayList<>();
        protected Map<String, Object> additionalHeaders = new HashMap<>();

        /**
         * The "jku" (JWK Set URL) Header Parameter is a URI that
         * refers to a resource for a set of JSON-encoded public keys, one of
         * which corresponds to the key used to digitally sign the JWS, or
         * the public key to which the JWE was encrypted
         */
        @JsonProperty(JSON_WEB_KEY_SET_URL)
        public BUILDER withJsonWebKeySetUrl(URI jsonWebKeySetUrl) {
            this.jsonWebKeySetUrl = jsonWebKeySetUrl;
            return builder;
        }

        /**
         * The "jwk" (JSON Web Key) Header Parameter is the public key that
         * corresponds to the key used to digitally sign the JWS, or the public
         * key to which the JWE was encrypted
         */
        @JsonProperty(JSON_WEB_KEY)
        public BUILDER withJsonWebKey(JWK<?> jsonWebKey) {
            this.jsonWebKey = jsonWebKey;
            return builder;
        }

        /**
         * The "typ" (type) Header Parameter is used to declare the MIME Media
         * Type of this complete JWS or JWE.
         */
        @JsonProperty(MEDIA_TYPE)
        public BUILDER withMediaType(MediaType mediaType) {
            this.mediaType = mediaType;
            return builder;
        }

        /**
         * The "cty" (content type) Header Parameter is used to declare the MIME
         * Media Type of the secured content (the payload).
         */
        @JsonProperty(CONTENT_MEDIA_TYPE)
        public BUILDER withContentMediaType(MediaType contentMediaType) {
            this.contentMediaType = contentMediaType;
            return builder;
        }

        /**
         * The "crit" (critical) Header Parameter indicates that extensions to
         * the initial RFC versions of the JWS or JWE specification are being
         * used that MUST be understood and processed.
         */
        @JsonIgnore
        public BUILDER withCriticalExtension(String criticalExtension) {
            this.criticalExtensions.add(criticalExtension);
            return builder;
        }

        /**
         * The "crit" (critical) Header Parameter indicates that extensions to
         * the initial RFC versions of the JWS or JWE specification are being
         * used that MUST be understood and processed.
         */
        @JsonProperty(CRITICAL_EXTENSIONS)
        public BUILDER withCriticalExtensions(List<String> criticalExtensions) {
            this.criticalExtensions.addAll(criticalExtensions);
            return builder;
        }

        /**
         * Additional headers found in this JWS or JEW header.
         */
        @JsonAnySetter
        public BUILDER withAdditionalHeaders(String name, Object value) {
            this.additionalHeaders.put(name, value);
            return builder;
        }

        /**
         * Return additional headers found in this JWS or JEW header.
         */
        @JsonIgnore
        public BUILDER withAdditionalHeaders(Map<String, Object> additionalHeaders) {
            this.additionalHeaders.putAll(additionalHeaders);
            return builder;
        }
    }
}
