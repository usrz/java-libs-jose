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

import static com.fasterxml.jackson.core.Base64Variants.MIME_NO_LINEFEEDS;
import static org.usrz.jose.jackson.ByteArraySerializer.serializeBytes;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;

public class X509CertificateSerializer
extends JsonSerializer<X509Certificate> {

    @Override
    public void serialize(X509Certificate value,
                          JsonGenerator generator,
                          SerializerProvider provider)
    throws IOException, JsonProcessingException {
        try {
            serializeBytes(value.getEncoded(), generator, MIME_NO_LINEFEEDS);
        } catch (CertificateEncodingException exception) {
            throw new JsonMappingException("Unable to serialize X509 certificate", exception);
        }
    }

    @Override
    public Class<X509Certificate> handledType() {
        return X509Certificate.class;
    }

}
