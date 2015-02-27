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
import static org.usrz.jose.jackson.BytesDeserializer.deserializeBytes;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonMappingException;

public class X509CertificateDeserializer extends JsonDeserializer<X509Certificate> {

    private static final CertificateFactory certificateFactory;
    static {
        try {
            certificateFactory = CertificateFactory.getInstance("X.509");
        } catch (CertificateException exception) {
            throw new IllegalStateException("Unable to access X.509 certificate factory");
        }
    }

    @Override
    public X509Certificate deserialize(JsonParser parser, DeserializationContext context)
    throws IOException, JsonProcessingException {
        final byte[] data = deserializeBytes(parser, MIME_NO_LINEFEEDS);
        final ByteArrayInputStream input = new ByteArrayInputStream(data);
        try {
            return (X509Certificate) certificateFactory.generateCertificate(input);
        } catch (CertificateException exception) {
            throw new JsonMappingException("Unable to parse X509 certificate", exception);
        }
    }

    @Override
    public Class<X509Certificate> handledType() {
        return X509Certificate.class;
    }

}
