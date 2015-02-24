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

import org.usrz.libs.configurations.Configurations;
import org.usrz.libs.configurations.ConfigurationsBuilder;
import org.usrz.libs.httpd.ServerStarter;
import org.usrz.libs.testing.NET;

public class TestServer {

    private final int port;
    private final ServerStarter server;

    public TestServer(String path)
    throws IOException {
        port = NET.serverPort();

        final Configurations configurations = new ConfigurationsBuilder()
                .put("server.name", "test-server")
                .put("server.listener.host", "127.0.0.1")
                .put("server.listener.port", port)
                .put("server.listener.secure", false)
                .put("server.json.use_timestamps", true)
                .put("server.json.field_naming", "underscores")
                .put("server.json.order_keys", true) // sanity for tests belok
            .build();

        server = new ServerStarter().start((builder) -> {

            builder.configure(configurations.strip("server"));

            builder.install((binder) -> {
                binder.bind(SessionManager.class).toInstance(new SessionManager() {});
            });

            /* Serve /rest1 with undescores & timestamps */
            builder.serveApp(path, (config) -> {
                config.setApplicationName("scram-login");
                config.register(FormScramLogin.class);
                config.register(JsonScramLogin.class);
            });
        });
    };

    public int getPort() {
        return port;
    }

    public void stop() {
        server.stop();
    }



}
