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

import java.math.BigInteger;
import java.security.cert.X509Certificate;

import javax.ws.rs.core.MediaType;

import org.usrz.jose.core.Bytes;
import org.usrz.jose.jws.JWSAlgorithm;

import com.fasterxml.jackson.databind.module.SimpleDeserializers;

public class JOSEDeserializers extends SimpleDeserializers {

    public JOSEDeserializers() {
        addDeserializer(Bytes.class, new BytesDeserializer());
        addDeserializer(BigInteger.class, new BigIntegerDeserializer());
        addDeserializer(MediaType.class, new MediaTypeDeserializer());
        addDeserializer(X509Certificate.class, new X509CertificateDeserializer());

        addDeserializer(JWSAlgorithm.class, new JOSEIdentifierDeserializer<JWSAlgorithm>(JWSAlgorithm.class));
    }

}
