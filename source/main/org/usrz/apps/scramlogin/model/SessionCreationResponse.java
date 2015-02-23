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
package org.usrz.apps.scramlogin.model;

import static org.usrz.libs.utils.codecs.Base64Codec.BASE_64;

import com.fasterxml.jackson.annotation.JsonProperty;

public class SessionCreationResponse {

    private final String sessionUrl;
    private final String hash;
    private final Object kdfSpec; // TODO
    private final String salt;
    private final String serverNonce;
    private final String sharedKey;

    public SessionCreationResponse(String sessionUrl,
                                   String hash,
                                   Object kdfSpec,
                                   byte[] salt,
                                   byte[] serverNonce,
                                   byte[] sharedKey) {
        this.sessionUrl = sessionUrl;
        this.hash = hash;
        this.kdfSpec = kdfSpec;
        this.salt = BASE_64.encode(salt);
        this.serverNonce = BASE_64.encode(serverNonce);
        this.sharedKey = BASE_64.encode(sharedKey);
    }

    @JsonProperty("session_url")
    public String getSessionUrl() {
        return sessionUrl;
    }

    @JsonProperty("hash")
    public String getHash() {
        return hash;
    }

    @JsonProperty("kdf_spec")
    public Object getKdfSpec() {
        return kdfSpec;
    }

    @JsonProperty("salt")
    public String getSalt() {
        return salt;
    }

    @JsonProperty("server_nonce")
    public String getServerNonce() {
        return serverNonce;
    }

    @JsonProperty("shared_key")
    public String getSharedKey() {
        return sharedKey;
    }

}
