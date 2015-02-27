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
import static org.usrz.jose.jackson.BytesDeserializer.deserializeBytes;

import java.io.IOException;
import java.math.BigInteger;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;

public class BigIntegerDeserializer extends JsonDeserializer<BigInteger> {

    @Override
    public BigInteger deserialize(JsonParser parser, DeserializationContext context)
    throws IOException, JsonProcessingException {
        final byte[] data = deserializeBytes(parser, MODIFIED_FOR_URL);
        return new BigInteger(1, data);
    }

    @Override
    public Class<BigInteger> handledType() {
        return BigInteger.class;
    }

}
