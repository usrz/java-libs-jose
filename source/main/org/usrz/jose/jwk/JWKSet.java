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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import lombok.Data;
import lombok.experimental.Accessors;

import org.usrz.jose.core.BeanBuilder;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;

/**
 * A JSON Web Key Set (JWK Set) is a JSON object that represents a set
 * of JWKs.
 */
@JsonDeserialize(builder=JWKSet.Builder.class)
public interface JWKSet {

    /** The {@code keys} JWK set field name. */
    public static final String KEYS = "keys";

    /**
     * The value of the "keys" member is an array of {@link JWK} values.
     */
    @JsonProperty(KEYS)
    public List<JWK<?>> getKeys();

    /* ====================================================================== */

    @Accessors(chain=true)
    @JsonPOJOBuilder(withPrefix="set")
    public class Builder
    extends BeanBuilder<JWKSet> {

        @SuppressWarnings("unused")
        private final List<JWK<?>> keys;
        private final List<JWK<?>> keysList;

        public Builder() {
            super(Impl.class);
            keysList = new ArrayList<>();
            keys = Collections.unmodifiableList(keysList);
        }

        @Override
        public JWKSet build() {
            return super.build();
        }

        /**
         * The value of the "keys" member is an array of {@link JWK} values.
         */
        @JsonProperty(KEYS)
        public Builder setKeys(List<JWK<?>> keys) {
            if (keys == null) return this;
            keys.forEach((criticalExtension) -> {
                keysList.add(criticalExtension);
            });
            return this;
        }

        /**
         * The value of the "keys" member is an array of {@link JWK} values.
         */
        @JsonIgnore
        public Builder addKey(JWK<?> key) {
            keysList.add(key);
            return this;
        }

        /* ================================================================== */

        @Data
        private static final class Impl implements JWKSet {
            private final List<JWK<?>> keys;
        }
    }
}
