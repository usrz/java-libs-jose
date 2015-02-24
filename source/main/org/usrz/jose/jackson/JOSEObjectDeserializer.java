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

import org.usrz.jose.AbstractObject;
import org.usrz.jose.jwk.AbstractJWK;
import org.usrz.jose.jws.JWSHeader;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.core.TreeNode;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;

public class JOSEObjectDeserializer extends JsonDeserializer<AbstractObject<?>> {

    @Override
    public AbstractObject<?> deserialize(JsonParser parser, DeserializationContext context)
    throws IOException, JsonProcessingException {

        final JsonToken token = parser.getCurrentToken();
        if (token != JsonToken.START_OBJECT) {
            throw context.mappingException(AbstractObject.class, token);
        }

        final TreeNode node = parser.readValueAsTree();
        final JsonParser json = node.traverse(parser.getCodec());
        json.nextToken();

        try {
            if (node.get("kty") != null) {
                return context.readValue(json, AbstractJWK.class);
//            } else if (node.get("enc") != null){
//                return context.readValue(json, JWEHeader.class);
            } else if (node.get("alg") != null) {
                return context.readValue(json, JWSHeader.class);
            } else {
                throw context.mappingException("Unknown JOSEObject (JWK/JWE/JWS) type");
            }
        } finally {
            json.close();
        }
    }
}
