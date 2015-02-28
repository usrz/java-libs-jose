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
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.ws.rs.core.MediaType;

import lombok.Setter;
import lombok.experimental.Accessors;

import org.usrz.jose.JOSEAlgorithm;
import org.usrz.jose.jwe.JWEAlgorithm;
import org.usrz.jose.jwk.JWK;
import org.usrz.jose.jws.JWSAlgorithm;

import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;

/**
 * An interface defining all common elements shared by all <i>JOSE</i> headers.
 *
 * @param <A> The type of the algorithm for this container, either a
 *            {@link JWSAlgorithm} or a {@link JWEAlgorithm}.
 */
public interface Header<A extends JOSEAlgorithm> extends Common<A> {

    /** The {@code typ} header field name. */
    public static final String MEDIA_TYPE = "typ";
    /** The {@code cty} header field name. */
    public static final String CONTENT_MEDIA_TYPE = "cty";
    /** The {@code crit} header field name. */
    public static final String CRITICAL_EXTENSIONS = "crit";
    /** The {@code jwk} header field name. */
    public static final String JSON_WEB_KEY = "jwk";
    /** The {@code jku} header field name. */
    public static final String JSON_WEB_KEY_SET_URL = "jku";

    /**
     * The "jku" (JWK Set URL) Header Parameter is a URI that
     * refers to a resource for a set of JSON-encoded public keys, one of
     * which corresponds to the key used to digitally sign the JWS, or
     * the public key to which the JWE was encrypted
     */
    @JsonProperty(JSON_WEB_KEY_SET_URL)
    public URI getJsonWebKeySetUrl();

    /**
     * The "jwk" (JSON Web Key) Header Parameter is the public key that
     * corresponds to the key used to digitally sign the JWS, or the public
     * key to which the JWE was encrypted
     */
    @JsonProperty(JSON_WEB_KEY)
    public JWK<?> getJsonWebKey();

    /**
     * The "typ" (type) Header Parameter is used to declare the MIME Media
     * Type of this complete JWS or JWE.
     */
    @JsonProperty(MEDIA_TYPE)
    public MediaType getMediaType();

    /**
     * The "cty" (content type) Header Parameter is used to declare the MIME
     * Media Type of the secured content (the payload).
     */
    @JsonProperty(CONTENT_MEDIA_TYPE)
    public MediaType getContentMediaType();

    /**
     * The "crit" (critical) Header Parameter indicates that extensions to
     * the initial RFC versions of the JWS or JWE specification are being
     * used that MUST be understood and processed.
     */
    @JsonProperty(CRITICAL_EXTENSIONS)
    public List<String> getCriticalExtensions();

    /**
     * Return additional headers found in this JWS or JEW header.
     */
    @JsonAnyGetter
    public Map<String, Object> getAdditionalHeaders();

    /* ====================================================================== */

    @Accessors(chain=true)
    @JsonPOJOBuilder(withPrefix="set")
    public abstract class Builder<A extends JOSEAlgorithm,
                                  H extends Header<A>,
                                  B extends Builder<A, H, B>>
    extends Common.Builder<A, H, B> {

        @SuppressWarnings("unused")
        private final List<String> criticalExtensions;
        private final List<String> criticalExtensionsList;

        @SuppressWarnings("unused")
        private final Map<String, Object> additionalHeaders;
        private final Map<String, Object> additionalHeadersMap;

        protected Builder(Class<? extends H> type) {
            super(type);

            criticalExtensionsList = new ArrayList<>();
            criticalExtensions = Collections.unmodifiableList(criticalExtensionsList);

            additionalHeadersMap = new HashMap<>();
            additionalHeaders = Collections.unmodifiableMap(additionalHeadersMap);
        }

        /* ================================================================== */

        /**
         * The "jku" (JWK Set URL) Header Parameter is a URI that
         * refers to a resource for a set of JSON-encoded public keys, one of
         * which corresponds to the key used to digitally sign the JWS, or
         * the public key to which the JWE was encrypted
         */
        @Setter(onMethod=@__({@JsonProperty(JSON_WEB_KEY_SET_URL)}))
        private URI jsonWebKeySetUrl;

        /**
         * The "jwk" (JSON Web Key) Header Parameter is the public key that
         * corresponds to the key used to digitally sign the JWS, or the public
         * key to which the JWE was encrypted
         */
        @Setter(onMethod=@__({@JsonProperty(JSON_WEB_KEY)}))
        private JWK<?> jsonWebKey;

        /**
         * The "typ" (type) Header Parameter is used to declare the MIME Media
         * Type of this complete JWS or JWE.
         */
        @Setter(onMethod=@__({@JsonProperty(MEDIA_TYPE)}))
        private MediaType mediaType;

        /**
         * The "cty" (content type) Header Parameter is used to declare the MIME
         * Media Type of the secured content (the payload).
         */
        @Setter(onMethod=@__({@JsonProperty(CONTENT_MEDIA_TYPE)}))
        private MediaType contentMediaType;

        /**
         * The "crit" (critical) Header Parameter indicates that extensions to
         * the initial RFC versions of the JWS or JWE specification are being
         * used that MUST be understood and processed.
         */
        @SuppressWarnings("unchecked")
        @JsonProperty(CRITICAL_EXTENSIONS)
        public B setCriticalExtensions(List<String> criticalExtensions) {
            if (criticalExtensions == null) return (B) this;
            criticalExtensions.forEach((criticalExtension) -> {
                criticalExtensionsList.add(criticalExtension);
            });
            return (B) this;
        }

        /**
         * The "crit" (critical) Header Parameter indicates that extensions to
         * the initial RFC versions of the JWS or JWE specification are being
         * used that MUST be understood and processed.
         */
        @JsonIgnore
        @SuppressWarnings("unchecked")
        public B addCriticalExtensions(String criticalExtension) {
            criticalExtensionsList.add(criticalExtension);
            return (B) this;
        }

        /**
         * Additional headers to be specified for this JWS or JWE header.
         */
        @JsonIgnore
        @SuppressWarnings("unchecked")
        public B setAdditionalHeaders(Map<String, Object> additionalHeaders) {
            if (additionalHeaders == null) return (B) this;
            additionalHeaders.forEach((headerName, headerValue) -> {
                additionalHeadersMap.put(headerName, headerValue);
            });
            return (B) this;
        }

        /**
         * Additional headers to be specified for this JWS or JWE header.
         */
        @JsonAnySetter
        @SuppressWarnings("unchecked")
        public B addAdditionalHeader(String headerName, Object headerValue) {
            additionalHeadersMap.put(headerName, headerValue);
            return (B) this;
        }
    }
}
