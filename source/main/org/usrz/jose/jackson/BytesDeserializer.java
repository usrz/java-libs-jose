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

import static com.fasterxml.jackson.core.Base64Variants.MODIFIED_FOR_URL;

import java.io.IOException;

import org.usrz.jose.core.Bytes;

import com.fasterxml.jackson.core.Base64Variant;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;

public class BytesDeserializer extends JsonDeserializer<Bytes> {

    @Override
    public Bytes deserialize(JsonParser parser, DeserializationContext context)
    throws IOException, JsonProcessingException {
        return new Bytes(deserializeBytes(parser, MODIFIED_FOR_URL));
    }

    @Override
    public Class<byte[]> handledType() {
        return byte[].class;
    }

    /*
     * Jackson does not seem to honor the call below, somehow...
     * final byte[] data = parser.getBinaryValue(Base64Variants.MIME_NO_LINEFEEDS);
     * Manually read a string and dencode base64
     */
    protected static final byte[] deserializeBytes(JsonParser parser, Base64Variant variant)
    throws IOException {
        return variant.decode(parser.getText());
    }
}
