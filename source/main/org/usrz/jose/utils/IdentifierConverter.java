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
package org.usrz.jose.utils;

import org.usrz.jose.JOSEIdentifier;

import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.type.TypeFactory;
import com.fasterxml.jackson.databind.util.StdConverter;

public abstract class IdentifierConverter<I extends JOSEIdentifier>//,
                                 //E extends Enum<E> & JOSEIdentifier>
extends StdConverter<String, I> {

    public IdentifierConverter() {
        final TypeFactory factory = TypeFactory.defaultInstance();
        final JavaType[] types = factory.findTypeParameters(IdentifierConverter.class, this.getClass());
        System.err.println("OUT[0] -> " + types[0]);
        System.err.println("OUT[0] -> " + types[1]);
    }

//    @Override
//    public I convert(String value) {
//        // TODO Auto-generated method stub
//        return null;
//    }


}
