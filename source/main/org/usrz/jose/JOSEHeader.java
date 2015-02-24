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
import java.util.List;
import java.util.Map;

import javax.ws.rs.core.MediaType;

import org.usrz.jose.jwk.JWK;

import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonProperty;

public interface JOSEHeader<ALGORITHM extends JOSEAlgorithm> extends JOSEObject<ALGORITHM> {

    public static final String CONTENT_MEDIA_TYPE = "cty";
    public static final String CRITICAL_EXTENSIONS = "crit";
    public static final String JSON_WEB_KEY = "jwk";
    public static final String JSON_WEB_KEY_SET_URL = "jku";
    public static final String MEDIA_TYPE = "typ";

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

}
