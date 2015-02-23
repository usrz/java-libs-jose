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

import com.fasterxml.jackson.annotation.JsonTypeInfo.Id;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.jsontype.impl.TypeIdResolverBase;
import com.fasterxml.jackson.databind.type.TypeFactory;

public class MyIdResolver extends TypeIdResolverBase {

    @Override
    public String idFromValue(Object value) {
        System.err.println("FROMVAL1 " + value);
        if (value instanceof Extra) {
            System.err.println("EXTRA-> " + ((Extra) value).getExtra());
            return ((Extra) value).getExtra();
        }
        // TODO Auto-generated method stub
        return "-----";
    }

    @Override
    public String idFromValueAndType(Object value, Class<?> suggestedType) {
        System.err.println("FROMVAL2 " + value);
        // TODO Auto-generated method stub
        return "wrong2";
    }

    @Override
    public Id getMechanism() {
        return Id.CUSTOM;
    }

    @Override
    public JavaType typeFromId(String id) {
        System.err.println("RESOLVING " + id);
        if (id != null) {
            return TypeFactory.defaultInstance().constructType(Extra.class);
        } else {
            return TypeFactory.defaultInstance().constructType(Empty.class);
        }
        //return null;
    }

}
