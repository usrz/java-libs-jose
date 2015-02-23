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

import javax.ws.rs.FormParam;

import com.fasterxml.jackson.annotation.JsonProperty;

public class SessionCreationRequest {

    private final String userId;
    private final String tenantId;
    private final byte[] clientNonce;

    public SessionCreationRequest(@JsonProperty("user_id")      @FormParam("user_id")      String userId,
                                  @JsonProperty("tenant_id")    @FormParam("tenant_id")    String tenantId,
                                  @JsonProperty("client_nonce") @FormParam("client_nonce") String clientNonce) {
        // TODO: throw 400 -> bad request
        this.userId = userId;
        this.tenantId = tenantId;
        this.clientNonce = BASE_64.decode(clientNonce);
    }

    public String getUserId() {
        return userId;
    }

    public String getTenantId() {
        return tenantId;
    }

    public byte[] getClientNonce() {
        return clientNonce;
    }

}
