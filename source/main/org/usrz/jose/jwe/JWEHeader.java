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
package org.usrz.jose.jwe;

import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;

import javax.ws.rs.core.MediaType;

import org.usrz.jose.JOSEHeader;
import org.usrz.jose.backup.JWEAlgorithm;
import org.usrz.jose.backup.JWECompression;
import org.usrz.jose.backup.JWEEncryption;
import org.usrz.jose.jwk.JWK;

import com.fasterxml.jackson.annotation.JsonProperty;

public class JWEHeader extends JOSEHeader<JWEAlgorithm> {

    private final JWEEncryption encryption;
    private final JWECompression compression;

    protected JWEHeader(final JWEAlgorithm algorithm,
                        final String keyID,
                        final URI x509URI,
                        final List<X509Certificate> x509CertificateChain,
                        final byte[] x509CertificateThumbprint,
                        final byte[] x509CertificateThumbprintSHA256,
                        final URI jwkSetURL,
                        final JWK jwk,
                        final MediaType type,
                        final MediaType contentType,
                        final List<String> criticalExtensions,
                        final Map<String, Object> additionalHeaders,
                        final JWEEncryption encryption,
                        final JWECompression compression) {
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
        this.encryption = encryption;
        this.compression = compression;
    }

    /**
     * The "enc" (encryption algorithm) Header Parameter identifies the
     * content encryption algorithm used to perform authenticated encryption
     * on the Plaintext to produce the Ciphertext and the Authentication Tag.
     */
    @JsonProperty("enc")
    public JWEEncryption getEncryption() {
        return encryption;
    }

    /**
     * The "zip" (compression algorithm) applied to the Plaintext before
     * encryption, if any.
     */
    @JsonProperty("zip")
    public JWECompression getCompression() {
        return compression;
    }

    public static class Builder extends JOSEHeader.Builder<JWEAlgorithm, JWEHeader, Builder> {

        protected JWEEncryption encryption;
        protected JWECompression compression;

        @Override
        public JWEHeader build() {
            return new JWEHeader(algorithm,
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
                                 additionalHeaders,
                                 encryption,
                                 compression);
        }

        /**
         * The "enc" (encryption algorithm) Header Parameter identifies the
         * content encryption algorithm used to perform authenticated encryption
         * on the Plaintext to produce the Ciphertext and the Authentication Tag.
         */
        @JsonProperty("enc")
        public Builder withEncryption(JWEEncryption encryption) {
            this.encryption = encryption;
            return builder;
        }

        /**
         * The "zip" (compression algorithm) applied to the Plaintext before
         * encryption, if any.
         */
        @JsonProperty("zip")
        public Builder withCompression(JWECompression compression) {
            this.compression = compression;
            return builder;
        }
    }
}
