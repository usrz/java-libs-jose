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

import lombok.Data;
import lombok.Setter;
import lombok.experimental.Accessors;

import org.usrz.jose.core.BeanBuilder;
import org.usrz.jose.core.Bytes;
import org.usrz.jose.core.Header;
import org.usrz.jose.jwk.JWK;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;

@JsonDeserialize(builder=JWEHeader.Builder.class)
public interface JWEHeader extends Header<JWEAlgorithm> {

    /** The {@code enc} JWE header field name. */
    public static final String ENCRYPTION = "enc";
    /** The {@code zip} JWE header field name. */
    public static final String COMPRESSION = "zip";

    /**
     * The "enc" (encryption algorithm) Header Parameter identifies the
     * content encryption algorithm used to perform authenticated encryption
     * on the Plaintext to produce the Ciphertext and the Authentication Tag.
     */
    @JsonProperty(ENCRYPTION)
    public JWEEncryption getEncryption();

    /**
     * The "zip" (compression algorithm) applied to the Plaintext before
     * encryption, if any.
     */
    @JsonProperty(ENCRYPTION)
    public JWECompression getCompression();

    /* ====================================================================== */

    @Accessors(chain=true)
    @JsonPOJOBuilder(withPrefix="set")
    public static final class Builder
    extends Header.Builder<JWEAlgorithm, JWEHeader, Builder> {

        private static final BeanBuilder<Builder, Impl> BUILDER = new BeanBuilder<>(Builder.class, Impl.class);

        /**
         * The "enc" (encryption algorithm) Header Parameter identifies the
         * content encryption algorithm used to perform authenticated encryption
         * on the Plaintext to produce the Ciphertext and the Authentication Tag.
         */
        @Setter(onMethod=@__({@JsonProperty(ENCRYPTION)}))
        private JWEEncryption encryption;

        /**
         * The "zip" (compression algorithm) applied to the Plaintext before
         * encryption, if any.
         */
        @Setter(onMethod=@__({@JsonProperty(COMPRESSION)}))
        private JWECompression compression;

        @Override
        public JWEHeader build() {
            return BUILDER.build(this);
        }

        @Data
        private static final class Impl implements JWEHeader {

            /* Common */
            private final JWEAlgorithm algorithm;
            private final String keyId;
            private final URI x509Url;
            private final List<X509Certificate> x509CertificateChain;
            private final Bytes x509CertificateThumbprint;
            private final Bytes x509CertificateThumbprintSHA256;

            /* Header */
            private final URI jsonWebKeySetUrl;
            private final JWK<?> jsonWebKey;
            private final MediaType mediaType;
            private final MediaType contentMediaType;
            private final List<String> criticalExtensions;
            private final Map<String, Object> additionalHeaders;

            /* JWE */
            private final JWEEncryption encryption;
            private final JWECompression compression;
        }
    }
}
