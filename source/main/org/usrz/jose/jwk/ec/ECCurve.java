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
package org.usrz.jose.jwk.ec;

import java.security.AlgorithmParameters;
import java.security.NoSuchAlgorithmException;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import org.usrz.jose.shared.JOSEIdentifier;

/**
 * The "kty" (key type) member identifies the cryptographic algorithm
 * family used with the key, such as "RSA" or "EC".
 *
 * @author <a href="mailto:pier@usrz.com">Pier Fumagalli</a>
 */
public enum ECCurve implements JOSEIdentifier {

    /** The NIST P-192 Elliptic Curve <i>(not specified in JOSE)</i> */
    P_192("P-192", "secp192r1"),
    /** The NIST P-224 Elliptic Curve <i>(not specified in JOSE)</i> */
    P_224("P-224", "secp224r1"),
    /** The NIST P-256 Elliptic Curve */
    P_256("P-256", "secp256r1"),
    /** The NIST P-384 Elliptic Curve */
    P_384("P-384", "secp384r1"),
    /** The NIST P-521 Elliptic Curve <i>(not 512)</i> */
    P_521("P-521", "secp521r1");

    /* ====================================================================== */

    private final String identifier;
    private final String standardName;
    private ECParameterSpec parameterSpec;

    private ECCurve(String identifier, String standardName) {
        this.identifier = identifier;
        this.standardName = standardName;
    }

    @Override
    public String joseName() {
        return identifier;
    }

    /**
     * Return the Java EC parameters specification of this curve.
     *
     * @throws NoSuchAlgorithmException If elliptic curves were not supported.
     * @throws InvalidParameterSpecException If the curve is unsupported.
     */
    public ECParameterSpec getECParameterSpec()
    throws NoSuchAlgorithmException, InvalidParameterSpecException {
        if (parameterSpec != null) return parameterSpec;
        final AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
        parameters.init(new ECGenParameterSpec(standardName));
        return parameterSpec = parameters.getParameterSpec(ECParameterSpec.class);
    }
}
