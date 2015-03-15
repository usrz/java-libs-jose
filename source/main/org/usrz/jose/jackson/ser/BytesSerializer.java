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

import static com.fasterxml.jackson.core.Base64Variants.MODIFIED_FOR_URL;

import java.io.IOException;

import org.usrz.jose.shared.Bytes;

import com.fasterxml.jackson.core.Base64Variant;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;

public class BytesSerializer
extends JsonSerializer<Bytes> {

    @Override
    public void serialize(Bytes value,
                          JsonGenerator generator,
                          SerializerProvider provider)
    throws IOException, JsonProcessingException {
        serializeBytes(value.getBytes(), generator, MODIFIED_FOR_URL);
    }

    @Override
    public Class<Bytes> handledType() {
        return Bytes.class;
    }

    /*
     * Jackson does not seem to honor the call below, somehow...
     * generator.writeBinary(Base64Variants.MIME_NO_LINEFEEDS, encoded, 0, encoded.length);
     * Manually encode base64 and write as string!
     */
    protected static final void serializeBytes(byte[] value,
                                               JsonGenerator generator,
                                               Base64Variant variant)
    throws IOException {
        generator.writeString(variant.encode(value));
    }

}
