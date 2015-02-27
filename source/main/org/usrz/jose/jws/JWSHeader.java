package org.usrz.jose.jws;

import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;

import javax.ws.rs.core.MediaType;

import lombok.Data;
import lombok.experimental.Accessors;

import org.usrz.jose.core.BeanBuilder;
import org.usrz.jose.core.Bytes;
import org.usrz.jose.core.Header;
import org.usrz.jose.jwk.JWK;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;

@JsonDeserialize(builder=JWSHeader.Builder.class)
public interface JWSHeader extends Header<JWSAlgorithm> {

    /* JWSHeader is a simple marker interface */

    /* ====================================================================== */

    @Accessors(chain=true)
    @JsonPOJOBuilder(withPrefix="set")
    public static final class Builder
    extends Header.Builder<JWSAlgorithm, JWSHeader, Builder> {

        private static final BeanBuilder<Builder, Impl> BUILDER = new BeanBuilder<>(Builder.class, Impl.class);

        @Override
        public JWSHeader build() {
            return BUILDER.build(this);
        }

        @Data
        private static final class Impl implements JWSHeader {

            /* Common */
            private final JWSAlgorithm algorithm;
            private final String keyId;
            private final URI x509Url;
            private final List<X509Certificate> x509CertificateChain;
            private final Bytes x509CertificateThumbprint;
            private final Bytes x509CertificateThumbprintSHA256;

            /* Header */
            private final URI jsonWebKeySetUrl;
            private final JWK<?> jsonWebKey;
            private final MediaType mediaType;
            private final MediaType contentMediaType;
            private final List<String> criticalExtensions;
            private final Map<String, Object> additionalHeaders;
        }
    }
}
