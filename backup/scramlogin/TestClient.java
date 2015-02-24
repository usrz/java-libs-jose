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
import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;

import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpContent;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpRequestFactory;
import com.google.api.client.http.UrlEncodedContent;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.http.json.JsonHttpContent;
import com.google.api.client.json.jackson2.JacksonFactory;

public class TestClient {

    private static final HttpRequestFactory FACTORY = new NetHttpTransport().createRequestFactory();
    private static final JacksonFactory JACKSON = new JacksonFactory();

    private final GenericUrl url;
    private HttpContent content;

    public TestClient(String url) {
        this.url = new GenericUrl(url);
    }

    public TestClient withPath(String path) {
        url.setRawPath(url.getRawPath() + "/" + path);
        return this;
    }

    public TestClient withForm(Consumer<Map<String, Object>> consumer) {
        final HashMap<String, Object> map = new HashMap<>();
        consumer.accept(map);
        content = new UrlEncodedContent(map);
        return this;
    }

    public TestClient withJson(Consumer<Map<String, Object>> consumer) {
        final HashMap<String, Object> map = new HashMap<>();
        consumer.accept(map);
        content = new JsonHttpContent(JACKSON, map);
        return this;
    };

    public HttpRequest get() throws IOException {
        return FACTORY.buildGetRequest(url);
    }

    public HttpRequest post() throws IOException {
        return FACTORY.buildPostRequest(url, content);
    }

}
