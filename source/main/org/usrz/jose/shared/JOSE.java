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
package org.usrz.jose.shared;

import org.usrz.jose.jwe.JWE;
import org.usrz.jose.jwe.JWEHeader;
import org.usrz.jose.jws.JWS;
import org.usrz.jose.jws.JWSHeader;

/**
 * The {@link JOSE} interface defines an abstract object formatted
 * according to the <i>Javascript Object Signing and Encryption</i>, or in
 * other words, the common aspects of {@link JWS} and {@link JWE} objects.
 *
 * @param <H> The type of the header for this container, either a
 *            {@link JWSHeader} or a {@link JWEHeader}.
 */
public interface JOSE<H extends JOSEHeader<?>> {

    /**
     * Return the header associated with this container.
     */
    public H getHeader();

}
