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

import javax.ws.rs.core.MediaType;

/**
 * A collection of {@link MediaType}s as described by the <i>Javascript
 * Object Signature and Encryption</i> set of specifications.
 */
public abstract class JOSEMediaTypes {

    /** The {@code application/jose} media type. */
    public static final String APPLICATION_JOSE = "application/jose";
    /** The {@code application/jwe} media type. */
    public static final String APPLICATION_JWE = "application/jwe";
    /** The {@code application/jws} media type. */
    public static final String APPLICATION_JWS = "application/jws";
    /** The {@code application/jwt} media type. */
    public static final String APPLICATION_JWT = "application/jwt";
    /** The {@code application/jose+json} media type. */
    public static final String APPLICATION_JOSE_JSON = "application/jose+json";
    /** The {@code application/jwe+json} media type. */
    public static final String APPLICATION_JWE_JSON = "application/jwe+json";
    /** The {@code application/jwk+json} media type. */
    public static final String APPLICATION_JWK_JSON = "application/jwk+json";
    /** The {@code application/jwk-set+json} media type. */
    public static final String APPLICATION_JWK_SET_JSON = "application/jwk-set+json";
    /** The {@code application/jws+json} media type. */
    public static final String APPLICATION_JWS_JSON = "application/jws+json";
    /** The {@code application/jwt+json} media type. */
    public static final String APPLICATION_JWT_JSON = "application/jwt+json";
    /** The {@code application/jose} media type. */
    public static final MediaType APPLICATION_JOSE_TYPE = MediaType.valueOf(APPLICATION_JOSE);
    /** The {@code application/jwe} media type. */
    public static final MediaType APPLICATION_JWE_TYPE = MediaType.valueOf(APPLICATION_JWE);
    /** The {@code application/jws} media type. */
    public static final MediaType APPLICATION_JWS_TYPE = MediaType.valueOf(APPLICATION_JWS);
    /** The {@code application/jwt} media type. */
    public static final MediaType APPLICATION_JWT_TYPE = MediaType.valueOf(APPLICATION_JWT);
    /** The {@code application/jose+json} media type. */
    public static final MediaType APPLICATION_JOSE_JSON_TYPE = MediaType.valueOf(APPLICATION_JOSE_JSON);
    /** The {@code application/jwe+json} media type. */
    public static final MediaType APPLICATION_JWE_JSON_TYPE = MediaType.valueOf(APPLICATION_JWE_JSON);
    /** The {@code application/jwk+json} media type. */
    public static final MediaType APPLICATION_JWK_JSON_TYPE = MediaType.valueOf(APPLICATION_JWK_JSON);
    /** The {@code application/jwk-set+json} media type. */
    public static final MediaType APPLICATION_JWK_SET_JSON_TYPE = MediaType.valueOf(APPLICATION_JWK_SET_JSON);
    /** The {@code application/jws+json} media type. */
    public static final MediaType APPLICATION_JWS_JSON_TYPE = MediaType.valueOf(APPLICATION_JWS_JSON);
    /** The {@code application/jwt+json} media type. */
    public static final MediaType APPLICATION_JWT_JSON_TYPE = MediaType.valueOf(APPLICATION_JWT_JSON);

    /* ====================================================================== */

    private JOSEMediaTypes() {
        throw new IllegalStateException("Do not construct");
    }
}
