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
package org.usrz.jose.jackson.deser;

import java.io.IOException;

import org.usrz.jose.jwk.JWK;
import org.usrz.jose.jwk.ec.ECPrivateJWK;
import org.usrz.jose.jwk.ec.ECPublicJWK;
import org.usrz.jose.jwk.oct.OctetSequenceJWK;
import org.usrz.jose.jwk.rsa.RSAPrivateJWK;
import org.usrz.jose.jwk.rsa.RSAPublicJWK;
import org.usrz.jose.shared.JOSEAbstract;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;

public class JWKDeserializer extends JsonDeserializer<JWK<?>> {

    @Override
    public JWK<?> deserialize(JsonParser parser, DeserializationContext context)
    throws IOException, JsonProcessingException {

        final JsonToken token = parser.getCurrentToken();
        if (token != JsonToken.START_OBJECT) {
            throw context.mappingException(JOSEAbstract.class, token);
        }

        final JsonNode node = parser.readValueAsTree();
        final JsonParser json = node.traverse(parser.getCodec());
        json.nextToken();

        System.err.println("PARSING ->" + node);
        try {
            final JsonNode typeNode = node.get(JWK.KEY_TYPE);
            if (typeNode == null) {
                throw context.mappingException("Missing \"" + JWK.KEY_TYPE + "\" property in JWK");
            }

            // TODO enums!
            final String type = typeNode.asText();
            switch (type) {
                case "EC":
                    return node.get(ECPrivateJWK.ECC_PRIVATE_KEY) != null ?
                            context.readValue(json, ECPrivateJWK.class) :
                            context.readValue(json, ECPublicJWK.class);

                case "RSA":
                    return node.get(RSAPrivateJWK.PRIVATE_EXPONENT) != null ?
                            context.readValue(json, RSAPrivateJWK.class) :
                            context.readValue(json, RSAPublicJWK.class);

                case "oct":
                    return context.readValue(json, OctetSequenceJWK.class);

                default: {
                }
            }

            /* We don't know how to map... */
            throw context.mappingException("Unknown JWK key type \"" + type + "\"");
        } finally {
            json.close();
        }
    }
}
