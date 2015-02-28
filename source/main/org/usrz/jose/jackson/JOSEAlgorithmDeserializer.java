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

import java.io.IOException;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;

import org.usrz.jose.JOSEAlgorithm;
import org.usrz.jose.jwe.JWEAlgorithm;
import org.usrz.jose.jws.JWSAlgorithm;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonMappingException;

public class JOSEAlgorithmDeserializer
extends JsonDeserializer<JOSEAlgorithm> {

    private final Map<String, JOSEAlgorithm> mappings;

    protected JOSEAlgorithmDeserializer() {
        final Map<String, JOSEAlgorithm> mappings = new HashMap<>();
        EnumSet.allOf(JWEAlgorithm.class).forEach((entry) -> {
            mappings.put(entry.joseId(), entry);
        });
        EnumSet.allOf(JWSAlgorithm.class).forEach((entry) -> {
            mappings.put(entry.joseId(), entry);
        });
        this.mappings = Collections.unmodifiableMap(mappings);
    }

    @Override
    public JOSEAlgorithm deserialize(JsonParser parser, DeserializationContext context)
    throws IOException, JsonProcessingException {
        final String text = parser.getText();
        final JOSEAlgorithm algorithm = mappings.get(text);
        if (algorithm != null) return algorithm;
        throw new JsonMappingException("Invalid algorithm value: " + text);
    }

    @Override
    public Class<JOSEAlgorithm> handledType() {
        return JOSEAlgorithm.class;
    }
}
