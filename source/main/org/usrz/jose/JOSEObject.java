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

import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.List;

import org.usrz.jose.jwe.JWE;
import org.usrz.jose.jwe.JWEAlgorithm;
import org.usrz.jose.jwk.JWK;
import org.usrz.jose.jws.JWS;
import org.usrz.jose.jws.JWSAlgorithm;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * The {@link JOSEObject} interface defines an abstract object defining all
 * the properties common to <i>JOSE</i> objects, such as {@link JWS}s,
 * {@link JWE}s and {@link JWK}s.
 *
 * @param <ALGORITHM> The type of the algorithm for this object, either a
 *                    {@link JWSAlgorithm} or a {@link JWEAlgorithm}.
 */
public interface JOSEObject<ALGORITHM extends JOSEAlgorithm> {

    public static final String ALGORITHM = "alg";
    public static final String KEY_ID = "kid";
    public static final String X509_CERTIFICATE_CHAIN = "x5c";
    public static final String X509_CERTIFICATE_THUMBPRINT = "x5t";
    public static final String X509_CERTIFICATE_THUMBPRINT_SHA256 = "x5t#S256";
    public static final String X509_URL = "x5u";

    /**
     * The "alg" (algorithm) member identifies the algorithm intended for
     * use with the JOSE object.
     */
    @JsonProperty(ALGORITHM)
    public ALGORITHM getAlgorithm();

    /**
     * The "kid" (key ID) member is used to match a specific key.
     */
    @JsonProperty(KEY_ID)
    public String getKeyId();

    /**
     * The "x5u" (X.509 URL) member is a URI that refers to a resource for an
     * X.509 public key certificate or certificate chain.
     *
     * The identified resource MUST provide a representation of the certificate
     * or certificate chain that conforms to RFC 5280 in PEM encoded form.
     */
    @JsonProperty(X509_URL)
    public URI getX509Url();

    /**
     * The "x5c" (X.509 Certificate Chain) member contains a chain of one or
     * more PKIX certificates.
     */
    @JsonProperty(X509_CERTIFICATE_CHAIN)
    public List<X509Certificate> getX509CertificateChain();

    /**
     * The "x5t" (X.509 Certificate SHA-1 Thumbprint) member is the SHA-1
     * thumbprint (a.k.a. digest) of the DER encoding of an X.509 certificate.
     */
    @JsonProperty(X509_CERTIFICATE_THUMBPRINT)
    public byte[] getX509CertificateThumbprint();

    /**
     * The "x5t#S256" (X.509 Certificate SHA-256 Thumbprint) member is the
     * SHA-256 thumbprint (a.k.a. digest) of the DER encoding of an X.509
     * certificate.
     */
    @JsonProperty(X509_CERTIFICATE_THUMBPRINT_SHA256)
    public byte[] getX509CertificateThumbprintSHA256();

}
