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
package org.usrz.jose.jackson;

import static org.usrz.jose.JOSEMediaTypes.APPLICATION_JOSE_JSON_TYPE;
import static org.usrz.jose.JOSEMediaTypes.APPLICATION_JOSE_TYPE;
import static org.usrz.jose.JOSEMediaTypes.APPLICATION_JWE_JSON_TYPE;
import static org.usrz.jose.JOSEMediaTypes.APPLICATION_JWE_TYPE;
import static org.usrz.jose.JOSEMediaTypes.APPLICATION_JWK_JSON_TYPE;
import static org.usrz.jose.JOSEMediaTypes.APPLICATION_JWK_SET_JSON_TYPE;
import static org.usrz.jose.JOSEMediaTypes.APPLICATION_JWS_JSON_TYPE;
import static org.usrz.jose.JOSEMediaTypes.APPLICATION_JWS_TYPE;
import static org.usrz.jose.JOSEMediaTypes.APPLICATION_JWT_JSON_TYPE;
import static org.usrz.jose.JOSEMediaTypes.APPLICATION_JWT_TYPE;

import java.io.IOException;

import javax.ws.rs.core.MediaType;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonMappingException;

public class MediaTypeDeserializer extends JsonDeserializer<MediaType> {

    @Override
    public MediaType deserialize(JsonParser parser, DeserializationContext context)
    throws IOException, JsonProcessingException {
        final String string = parser.getValueAsString();
        try {
            switch (string.toUpperCase()) {
                case "JOSE":         return APPLICATION_JOSE_TYPE;
                case "JOSE+JSON":    return APPLICATION_JOSE_JSON_TYPE;
                case "JWE":          return APPLICATION_JWE_TYPE;
                case "JWE+JSON":     return APPLICATION_JWE_JSON_TYPE;
                case "JWK+JSON":     return APPLICATION_JWK_JSON_TYPE;
                case "JWK-SET+JSON": return APPLICATION_JWK_SET_JSON_TYPE;
                case "JWS":          return APPLICATION_JWS_TYPE;
                case "JWS+JSON":     return APPLICATION_JWS_JSON_TYPE;
                case "JWT":          return APPLICATION_JWT_TYPE;
                case "JWT+JSON":     return APPLICATION_JWT_JSON_TYPE;
            }
            if (string.indexOf('/') < 0) {
                return MediaType.valueOf("application/" + string);
            } else {
                return MediaType.valueOf(string);
            }
        } catch (Exception exception) {
            throw new JsonMappingException("Invalid content type: " + string, exception);
        }
    }

    @Override
    public Class<MediaType> handledType() {
        return MediaType.class;
    }

}
