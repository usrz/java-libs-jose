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

import org.usrz.jose.JOSEIdentifier;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;

public class JOSEIdentifierSerializer //<I extends Enum<I> & JOSEIdentifier>
extends JsonSerializer<JOSEIdentifier> {

//    private final Class<I> type;
//
//    protected JOSEIdentifierSerializer(Class<I> type) {
//        this.type = type;
//    }

    @Override
    public void serialize(JOSEIdentifier value,
                          JsonGenerator generator,
                          SerializerProvider provider)
    throws IOException, JsonProcessingException {
        generator.writeString(value.getIdentifier());
    }

    @Override
    public Class<JOSEIdentifier> handledType() {
        return JOSEIdentifier.class;
        //return type;
    }
}
