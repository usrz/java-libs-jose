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


public abstract class JOSEMediaTypes {

    public static final String APPLICATION_JOSE = "application/jose";
    public static final String APPLICATION_JWE  = "application/jwe";
    public static final String APPLICATION_JWK  = "application/jwk";
    public static final String APPLICATION_JWS  = "application/jws";
    public static final String APPLICATION_JWT  = "application/jwt";

    public static final String APPLICATION_JOSE_JSON = "application/jose+json";
    public static final String APPLICATION_JWE_JSON  = "application/jwe+json";
    public static final String APPLICATION_JWK_JSON  = "application/jwk+json";
    public static final String APPLICATION_JWS_JSON  = "application/jws+json";
    public static final String APPLICATION_JWT_JSON  = "application/jwt+json";

    public static final MediaType APPLICATION_JOSE_TYPE = MediaType.valueOf(APPLICATION_JOSE);
    public static final MediaType APPLICATION_JWE_TYPE  = MediaType.valueOf(APPLICATION_JWE);
    public static final MediaType APPLICATION_JWK_TYPE  = MediaType.valueOf(APPLICATION_JWK);
    public static final MediaType APPLICATION_JWS_TYPE  = MediaType.valueOf(APPLICATION_JWS);
    public static final MediaType APPLICATION_JWT_TYPE  = MediaType.valueOf(APPLICATION_JWT);

    public static final MediaType APPLICATION_JOSE_JSON_TYPE = MediaType.valueOf(APPLICATION_JOSE_JSON);
    public static final MediaType APPLICATION_JWE_JSON_TYPE  = MediaType.valueOf(APPLICATION_JWE_JSON);
    public static final MediaType APPLICATION_JWK_JSON_TYPE  = MediaType.valueOf(APPLICATION_JWK_JSON);
    public static final MediaType APPLICATION_JWS_JSON_TYPE  = MediaType.valueOf(APPLICATION_JWS_JSON);
    public static final MediaType APPLICATION_JWT_JSON_TYPE  = MediaType.valueOf(APPLICATION_JWT_JSON);
}
