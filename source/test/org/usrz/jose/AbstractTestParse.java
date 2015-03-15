package org.usrz.jose;

import java.math.BigInteger;
import java.net.URL;

import org.usrz.jose.jackson.JOSEObjectMapper;
import org.usrz.jose.shared.Bytes;
import org.usrz.libs.testing.AbstractTest;
import org.usrz.libs.utils.codecs.Base64Codec;

import com.fasterxml.jackson.core.PrettyPrinter;
import com.fasterxml.jackson.core.TreeNode;
import com.fasterxml.jackson.core.util.DefaultPrettyPrinter;

public class AbstractTestParse extends AbstractTest {

    protected final JOSEObjectMapper mapper = new JOSEObjectMapper();
    protected final PrettyPrinter prettyPrinter = new DefaultPrettyPrinter();
    protected final Base64Codec base64 = new Base64Codec(Base64Codec.Alphabet.URL_SAFE);

    protected URL getResource(String name) {
        final URL url = this.getClass().getResource(name);
        assertNotNull(url, "Resource " + name + " not found");
        return url;
    }

    protected void validateObject(String json, Object object)
    throws Exception {
        validateObject(mapper.readTree(json), object);
    }

    protected void validateObject(URL url, Object object)
    throws Exception {
        validateObject(mapper.readTree(url), object);
    }

    protected void validateObject(TreeNode expected, Object object)
    throws Exception {
        final TreeNode actual = mapper.valueToTree(object);

        if (!actual.equals(expected)) {
            final String actualString = mapper.writer(prettyPrinter).writeValueAsString(actual);
            final String expectedString = mapper.writer(prettyPrinter).writeValueAsString(expected);
            throw new AssertionError("Tree differs:\n>>> EXPECTED >>>\n" + expectedString + "\n<<< ACTUAL <<<\n" + actualString);
        } else {
            System.err.println("Validated:");
            System.err.println(mapper.writer(prettyPrinter).writeValueAsString(actual));
        }
    }

    protected Bytes parseBytes(String bytes) {
        return new Bytes(base64.decode(bytes));
    }

    protected BigInteger parseBigInteger(String bigInteger) {
        return new BigInteger(1, base64.decode(bigInteger));
    }
}
