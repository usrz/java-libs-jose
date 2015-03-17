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

import lombok.Data;
import lombok.Setter;
import lombok.experimental.Accessors;

import org.usrz.jose.shared.Bytes;
import org.usrz.jose.shared.JOSE;
import org.usrz.jose.shared.JOSEBuilder;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;

/**
 * A JSON Web Signature ({@link JWS}) represents content secured with digital
 * signatures or Message Authentication Codes (MACs) using JavaScript Object
 * Notation (JSON) based data structures.
 */
@JsonDeserialize(builder=JWS.Builder.class)
public interface JWS extends JOSE<JWSHeader> {

    /** The {@code protected} field name. */
    public static final String PAYLOAD = "payload";

    /** The {@code protected} field name. */
    public static final String SIGNATURE = "signature";

    /**
     * Return the signed payload.
     */
    @JsonProperty(PAYLOAD)
    public Bytes getPayload();

    /**
     * Return the payload's signature.
     */
    @JsonProperty(SIGNATURE)
    public Bytes getSignature();

    /* ====================================================================== */

    /** A builder of immutable {@link JWS} instances. */
    @Accessors(chain=true)
    @JsonPOJOBuilder(withPrefix="set")
    public static final class Builder
    extends JOSEBuilder<JWS> {

        public Builder() {
            super(Impl.class);
        }

        /* ================================================================== */

        /** The {@link JWS} header */
        @Setter(onMethod=@__({@JsonProperty(PROTECTED_HEADER)}))
        private JWSHeader header;

        /** The signed payload. */
        @Setter(onMethod=@__({@JsonProperty(PAYLOAD)}))
        private Bytes payload;

        /** The payload's signature */
        @Setter(onMethod=@__({@JsonProperty(SIGNATURE)}))
        private Bytes signature;

        /* ================================================================== */

        @Override
        public JWS build() {
            return super.build();
        }

        /* ================================================================== */

        @Data
        private static final class Impl implements JWS {

            private final JWSHeader header;
            private final Bytes payload;
            private final Bytes signature;

        }
    }
}
