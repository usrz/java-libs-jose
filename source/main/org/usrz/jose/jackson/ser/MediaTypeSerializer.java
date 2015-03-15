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
package org.usrz.jose.jackson.ser;

import java.io.IOException;

import javax.ws.rs.core.MediaType;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;

public class MediaTypeSerializer
extends JsonSerializer<MediaType> {

    @Override
    public void serialize(MediaType value,
                          JsonGenerator generator,
                          SerializerProvider provider)
    throws IOException, JsonProcessingException {
        if (value == null) {
            generator.writeNull();
        } else {
            final String string = value.toString();
            if (string.startsWith("application/")) {
                final String substring = string.substring(12);
                if (substring.indexOf('/') < 0) {
                    switch(substring.toUpperCase()) {
                        case "JOSE":      generator.writeString("JOSE");      break;
                        case "JOSE+JSON": generator.writeString("JOSE+JSON"); break;
                        case "JWE":       generator.writeString("JWE");       break;
                        case "JWE+JSON":  generator.writeString("JWE+JSON");  break;
                        case "JWK":       generator.writeString("JWK");       break;
                        case "JWK+JSON":  generator.writeString("JWK+JSON");  break;
                        case "JWS":       generator.writeString("JWS");       break;
                        case "JWS+JSON":  generator.writeString("JWS+JSON");  break;
                        case "JWT":       generator.writeString("JWT");       break;
                        case "JWT+JSON":  generator.writeString("JWT+JSON");  break;
                        default:          generator.writeString(substring);   break;
                    }
                    return;
                }
            }
            generator.writeString(string);
        }
    }

    @Override
    public Class<MediaType> handledType() {
        return MediaType.class;
    }

}