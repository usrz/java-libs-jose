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
package org.usrz.jose;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.Key;
import java.security.KeyFactory;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.testng.annotations.Test;
import org.usrz.libs.utils.codecs.Base64Codec;

public class ECCurves {

    @Test
    public void testMe() throws Throwable {

        final BigInteger x = new BigInteger(1, Base64Codec.BASE_64.decode("gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0"));
        final BigInteger y = new BigInteger(1, Base64Codec.BASE_64.decode("SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps"));
        final BigInteger d = new BigInteger(1, Base64Codec.BASE_64.decode("0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo"));

        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
        parameters.init(new ECGenParameterSpec("secp256r1"));
        ECParameterSpec ecParameters = parameters.getParameterSpec(ECParameterSpec.class);

        final Key pub = KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(new ECPoint(x, y), ecParameters));
        final Key pri = KeyFactory.getInstance("EC").generatePrivate(new ECPrivateKeySpec(d, ecParameters));
        System.err.println("X->" + x);
        System.err.println("Y->" + y);
        System.err.println("D->" + d);
        System.err.println("PUB->" + pub.getClass().getName() + "/" + pub.getFormat() + " --> " + pub);
        System.err.println("PRI->" + pri.getClass().getName() + "/" + pri.getFormat() + " --> " + pri);
        System.err.println("SPEC->" + ((ECPrivateKey) pri).getParams());

        byte[] pubenc = pub.getEncoded();
        byte[] prienc = pri.getEncoded();

        final X509EncodedKeySpec pubspec = new X509EncodedKeySpec(pubenc);
        final PKCS8EncodedKeySpec prispec = new PKCS8EncodedKeySpec(prienc);

        KeyFactory keyFactory = KeyFactory.getInstance("EC");

        final Key pub2 = keyFactory.generatePublic(pubspec);
        final Key pri2 = keyFactory.generatePrivate(prispec);

        System.err.println("PUB2->" + pub2.getClass().getName() + "/" + pub2.getFormat() + " --> " + pub2);
        System.err.println("PRI2->" + pri2.getClass().getName() + "/" + pri2.getFormat() + " --> " + pri2);
        System.err.println("SPEC2->" + ((ECPrivateKey) pri2).getParams());



    }
}
