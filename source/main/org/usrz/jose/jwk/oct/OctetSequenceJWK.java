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
package org.usrz.jose.jwk.oct;

import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.crypto.SecretKey;

import lombok.Data;
import lombok.Setter;
import lombok.experimental.Accessors;

import org.usrz.jose.core.BeanBuilder;
import org.usrz.jose.core.Bytes;
import org.usrz.jose.jwe.JWEAlgorithm;
import org.usrz.jose.jwk.JWK;
import org.usrz.jose.jwk.JWKKeyOperation;
import org.usrz.jose.jwk.JWKKeyType;
import org.usrz.jose.jwk.JWKPublicKeyUse;
import org.usrz.jose.jwk.JWK.Builder;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;

public interface OctetSequenceJWK extends JWK<SecretKey> {

    /** The {@code k} JWK <i>("{@code oct}")</i> field name. */
    public static final String KEY_VALUE = "k";

    /**
     * The "k" (key value) member contains the value of the symmetric (or
     * other single-valued) key.
     */
    @JsonProperty(KEY_VALUE)
    public Bytes getKeyValue();

    /* ====================================================================== */

    @Accessors(chain=true)
    @JsonPOJOBuilder(withPrefix="set")

    public static final class Builder
    extends JWK.Builder<SecretKey, OctetSequenceJWK, Builder> {

        private static final BeanBuilder<Builder, Impl> BUILDER = new BeanBuilder<>(Builder.class, Impl.class);

        /**
         * The "k" (key value) member contains the value of the symmetric (or
         * other single-valued) key.
         */
        @Setter(onMethod=@__({@JsonProperty(KEY_VALUE)}))
        private Builder keyValue;

        @Override
        public OctetSequenceJWK build() {
            return BUILDER.build(this);
        }

        @Data
        private static final class Impl implements OctetSequenceJWK {

            /* Common */
            private final JWEAlgorithm algorithm;
            private final String keyId;
            private final URI x509Url;
            private final List<X509Certificate> x509CertificateChain;
            private final Bytes x509CertificateThumbprint;
            private final Bytes x509CertificateThumbprintSHA256;

            /* JWK */
            private final JWKKeyType keyType;
            private final JWKPublicKeyUse publicKeyUse;
            private final List<JWKKeyOperation> keyOperations;

            /* JWK "oct" */
            private final Bytes keyValue;
        }
    }
}
