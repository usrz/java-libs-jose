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
package org.usrz.apps.scramlogin;

import java.io.IOException;

import org.testng.annotations.Test;

import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpResponse;

public class SimpleTest extends TestWithServer {

    @Test
    public void testForm() throws IOException {
        HttpRequest request = connect().withForm((map) -> {
            map.put("version", 1);
            map.put("request", "foobarbaz");
        }).post();
        final HttpResponse response = request.execute();
        System.out.println(response.getHeaders().getLocation());
    }

    @Test
    public void testJson() throws IOException {
        HttpRequest request = connect().withJson((map) -> {
            map.put("version", 1);
            map.put("request", "foobarbaz");
        }).post();
        final HttpResponse response = request.execute();
        System.out.println(response.getHeaders().getLocation());
    }

    @Test
    public void testFormSlash() throws IOException {
        HttpRequest request = connect().withPath("").withForm((map) -> {
            map.put("version", 1);
            map.put("request", "foobarbaz");
        }).post();
        final HttpResponse response = request.execute();
        System.out.println(response.getHeaders().getLocation());
    }

    @Test
    public void testJsonSlash() throws IOException {
        HttpRequest request = connect().withPath("").withJson((map) -> {
            map.put("version", 1);
            map.put("request", "foobarbaz");
        }).post();
        final HttpResponse response = request.execute();
        System.out.println(response.getHeaders().getLocation());
    }
}
