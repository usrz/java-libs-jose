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

import org.usrz.jose.jackson.deser.JOSEDeserializers;
import org.usrz.jose.jackson.ser.JOSESerializers;

import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.core.Base64Variants;
import com.fasterxml.jackson.databind.ObjectMapper;

public class JOSEObjectMapper extends ObjectMapper {

    public static final JOSEObjectMapper MAPPER = new JOSEObjectMapper();

    public JOSEObjectMapper() {
        setBase64Variant(Base64Variants.MODIFIED_FOR_URL);
        setSerializationInclusion(Include.NON_EMPTY);

        /*
         * We don't want to use a module here, as they seem to be shared across
         * all mappers (or, somehow, even after a "copy()" their addition causes
         * the behavior of the parent to be modified. Do it manually...
         */
        _serializerFactory = _serializerFactory
                .withAdditionalSerializers(new JOSESerializers());
        _serializerProvider = _serializerProvider.createInstance(
                getSerializationConfig(), _serializerFactory);

        /* Our deserialization context */
        _deserializationContext = _deserializationContext
                .with(_deserializationContext.getFactory()
                            .withAdditionalDeserializers(new JOSEDeserializers()));
    }

}
