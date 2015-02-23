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

import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.usrz.libs.testing.AbstractTest;

public class TestWithServer extends AbstractTest {

    private TestServer server;

    @BeforeClass
    public final void startServer()
    throws IOException {
        server = new TestServer("/login");
    }

    @AfterClass
    protected final void stopServer() {
        if (server != null) server.stop();
    }

    protected TestClient connect()
    throws IOException {
        return new TestClient("http://127.0.0.1:" + server.getPort() + "/login");
    }

}
