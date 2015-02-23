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
package org.usrz.jose.backup;

import org.usrz.jose.JOSEIdentifier;
import org.usrz.jose.backup.JWKKeyType.Converter;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.util.StdConverter;

/**
 * The "kty" (key type) member identifies the cryptographic algorithm
 * family used with the key, such as "RSA" or "EC".
 *
 * @author <a href="mailto:pier@usrz.com">Pier Fumagalli</a>
 */
@JsonDeserialize(converter = Converter.class)
public interface JWKKeyType extends JOSEIdentifier {

    /**
     * This enumeration is the set of "kty" (key type) parameter values that
     * are defined for use in JWKs.
     *
     * @author <a href="mailto:pier@usrz.com">Pier Fumagalli</a>
     */
    public enum Type implements JWKKeyType {
        /** Elliptic Curve */
        EC("EC"),
        /** RSA */
        RSA("RSA"),
        /** Octet sequence (used to represent symmetric keys) */
        OCT("oct");

        private final String identifier;

        private Type(String identifier) {
            this.identifier = identifier;
        }

        @Override
        public String getIdentifier() {
            return identifier;
        }
    }

    public class Converter extends StdConverter<String, Type> {
//    public class Converter extends IdentifierConverter<JWKKeyType> { //, Type> {

        @Override
        public Type convert(String value) {
            if (value == null) return null;
            switch (value.toUpperCase()) {
                case "EC": return Type.EC;
                case "RSA": return Type.RSA;
                case "OCT": return Type.OCT;
            }
            throw new IllegalArgumentException("Unsupported " + value);
        }
    }
}
