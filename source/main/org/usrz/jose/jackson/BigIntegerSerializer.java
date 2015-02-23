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
import static org.usrz.jose.jackson.ByteArraySerializer.serializeBytes;

import java.io.IOException;
import java.math.BigInteger;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;

public class BigIntegerSerializer extends JsonSerializer<BigInteger> {

    @Override
    public void serialize(BigInteger value,
                          JsonGenerator generator,
                          SerializerProvider provider)
    throws IOException, JsonProcessingException {
        final byte[] encoded = value.toByteArray();
        if ((encoded.length > 1) && (encoded[0] == 0)) {
            final byte[] nonnegative = new byte[encoded.length - 1];
            System.arraycopy(encoded, 1, nonnegative, 0, nonnegative.length);
            serializeBytes(nonnegative, generator, MODIFIED_FOR_URL);
        } else {
            serializeBytes(encoded, generator, MODIFIED_FOR_URL);
        }
    }

    @Override
    public Class<BigInteger> handledType() {
        return BigInteger.class;
    }

}
