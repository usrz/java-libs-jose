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

import java.net.URL;

import org.testng.annotations.Test;
import org.usrz.jose.AbstractTestParse;

public class JWKTest extends AbstractTestParse {

    @Test
    public void testAppendix_A3()
    throws Exception {
        final URL url = getResource("jwk-appendix-a3-symmetric-keys.json");
        final JWKSet keys = mapper.readValue(url, JWKSet.class);
        validateObject(url, keys);

    }
}
