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

import java.net.URI;

import org.testng.annotations.Test;

import com.fasterxml.jackson.databind.ObjectMapper;

public class BigIntegerTest {

    final ObjectMapper mapper = new ObjectMapper();


    @Test
    public void deserializeEC()
    throws Exception {

        final ObjectMapper mapper = new ObjectMapper();

        final MyFoo foo = mapper.readValue("{\"myURI\":\"http://www/\"}", MyFoo.class);
        System.err.println(foo.uri);

        System.err.println(mapper.writeValueAsString(foo));



    }

    public static final class MyFoo {
        private URI uri;

        public URI getMyURI() {
            return uri;
        }

        public void setMyURI(URI uri) {
           this.uri = uri;
        }
    }

}
