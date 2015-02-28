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
package org.usrz.jose.jwk;

import java.security.Key;
import java.util.List;

import lombok.Setter;
import lombok.experimental.Accessors;

import org.usrz.jose.JOSEAlgorithm;
import org.usrz.jose.core.Common;
import org.usrz.jose.jackson.JWKDeserializer;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;

/**
 * A JSON Web Key (JWK) is a JavaScript Object Notation (JSON) data
 * structure that represents a cryptographic key.
 *
 * @param <K> The Java {@link Key} type represented by this {@link JWK}
 */
@JsonDeserialize(using=JWKDeserializer.class)
public interface JWK<K extends Key> extends Common<JOSEAlgorithm> {

    /** The {@code key_ops} JWK field name. */
    public static final String KEY_OPERATIONS = "key_ops";
    /** The {@code kty} JWK field name. */
    public static final String KEY_TYPE = "kty";
    /** The {@code use} JWK field name. */
    public static final String PUBLIC_KEY_USE = "use";

    /**
     * The "kty" (key type) member identifies the cryptographic algorithm
     * family used with the key.
     */
    @JsonProperty(KEY_TYPE)
    public JWKKeyType getKeyType();

    /**
     * The "use" (public key use) member identifies the intended use of the
     * public key.
     */
    @JsonProperty(PUBLIC_KEY_USE)
    public JWKPublicKeyUse getPublicKeyUse();

    /**
     * The "key_ops" (key operations) member identifies the operation(s)
     * that the key is intended to be used for.
     */
    @JsonProperty(KEY_OPERATIONS)
    public List<JWKKeyOperation> getKeyOperations();

    @Accessors(chain=true)
    public abstract static class Builder<K extends Key,
                                         J extends JWK<K>,
                                         B extends Builder<K, J, B>>
    extends Common.Builder<JOSEAlgorithm, J, B> {

        protected Builder(Class<? extends J> type) {
            super(type);
        }

        /* ================================================================== */

        /**
         * The "kty" (key type) member identifies the cryptographic algorithm
         * family used with the key.
         */
        @Setter(onMethod=@__({@JsonProperty(KEY_TYPE)}))
        private JWKKeyType keyType;

        /**
         * The "use" (public key use) member identifies the intended use of the
         * public key.
         */
        @Setter(onMethod=@__({@JsonProperty(PUBLIC_KEY_USE)}))
        private JWKPublicKeyUse publicKeyUse;

        /**
         * The "key_ops" (key operations) member identifies the operation(s)
         * that the key is intended to be used for.
         */
        @Setter(onMethod=@__({@JsonProperty(KEY_OPERATIONS)}))
        private List<JWKKeyOperation> keyOperations;

    }
}
