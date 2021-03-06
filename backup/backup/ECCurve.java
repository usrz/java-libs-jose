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


/**
 * The "crv" (curve) member identifies the cryptographic curve used with
 * the key.
 *
 * @author <a href="mailto:pier@usrz.com">Pier Fumagalli</a>
 */
public interface ECCurve extends JOSEIdentifier {

    /**
     * This enumeration is the set of "crv" (curve) parameter values that
     * are defined for use in Elliptic Curve JWKs.
     *
     * @author <a href="mailto:pier@usrz.com">Pier Fumagalli</a>
     */
    public enum Type implements ECCurve {
        /** Prime size 256 bits. */
        P_256("P-256"),
        /** Prime size 384 bits. */
        P_384("P-384"),
        /** Prime size 521 bits <i>(not 512)</i>. */
        P_521("P-521");

        private final String identifier;

        private Type(String identifier) {
            this.identifier = identifier;
        }

        @Override
        public String getIdentifier() {
            return identifier;
        }
    }

}
