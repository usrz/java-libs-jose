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

import org.usrz.jose.shared.Bytes;
import org.usrz.jose.shared.JOSE;

/**
 * A JSON Web Encryption ({@link JWE}) represents encrypted content using
 * JavaScript Object Notation (JSON) based data structures.
 */
public interface JWE extends JOSE<JWEHeader> {

    public Bytes getEncryptedKey();

    public Bytes getInitializationVector();

    public Bytes getCipherText();

    public Bytes getAuthenticationTag();

}
