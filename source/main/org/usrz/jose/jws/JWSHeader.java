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
package org.usrz.jose.jws;

import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;

import javax.ws.rs.core.MediaType;

import org.usrz.jose.AbstractJOSEHeader;
import org.usrz.jose.jwk.JWK;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;

@JsonDeserialize(builder=JWSHeader.Builder.class)
public class JWSHeader extends AbstractJOSEHeader<JWSAlgorithm> {

    protected JWSHeader(final JWSAlgorithm algorithm,
                        final String keyID,
                        final URI x509URI,
                        final List<X509Certificate> x509CertificateChain,
                        final byte[] x509CertificateThumbprint,
                        final byte[] x509CertificateThumbprintSHA256,
                        final URI jwkSetURL,
                        final JWK<?> jwk,
                        final MediaType type,
                        final MediaType contentType,
                        final List<String> criticalExtensions,
                        final Map<String, Object> additionalHeaders) {
        super(algorithm,
              keyID,
              x509URI,
              x509CertificateChain,
              x509CertificateThumbprint,
              x509CertificateThumbprintSHA256,
              jwkSetURL,
              jwk,
              type,
              contentType,
              criticalExtensions,
              additionalHeaders);
        if (algorithm == null) throw new IllegalArgumentException("Missing algorithm");
        criticalExtensions.forEach((extension) -> {
            if (additionalHeaders.containsKey(extension)) return;
            throw new IllegalArgumentException("Missing value for critical extension \"" + extension + "\"");
        });
    }

    public static class Builder extends AbstractJOSEHeader.Builder<JWSAlgorithm, JWSHeader, Builder> {

        @Override
        public JWSHeader build() {
            return new JWSHeader(algorithm,
                                 keyId,
                                 x509Url,
                                 x509CertificateChain,
                                 x509CertificateThumbprint,
                                 x509CertificateThumbprintSHA256,
                                 jsonWebKeySetUrl,
                                 jsonWebKey,
                                 mediaType,
                                 contentMediaType,
                                 criticalExtensions,
                                 additionalHeaders);
        }
    }
}
