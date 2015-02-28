package org.usrz.jose;

import java.net.URL;

import org.usrz.jose.jackson.JOSEObjectMapper;
import org.usrz.libs.testing.AbstractTest;

import com.fasterxml.jackson.core.PrettyPrinter;
import com.fasterxml.jackson.core.TreeNode;
import com.fasterxml.jackson.core.util.DefaultPrettyPrinter;

public class AbstractTestParse extends AbstractTest {

    protected final JOSEObjectMapper mapper = new JOSEObjectMapper();
    protected final PrettyPrinter prettyPrinter = new DefaultPrettyPrinter();

    protected URL getResource(String name) {
        final URL url = this.getClass().getResource(name);
        assertNotNull(url, "Resource " + name + " not found");
        return url;
    }

    protected void validateObject(URL url, Object object)
    throws Exception {
        final TreeNode actual = mapper.valueToTree(object);
        final TreeNode expected = mapper.readTree(url);

        if (!actual.equals(expected)) {
            final String actualString = mapper.writer(prettyPrinter).writeValueAsString(actual);
            final String expectedString = mapper.writer(prettyPrinter).writeValueAsString(expected);
            throw new AssertionError("Tree differs: " + url + "\n>>> EXPECTED >>>\n" + expectedString + "\n<<< ACTUAL <<<\n" + actualString);
        } else {
            System.err.println("Validated " + url);
            System.err.println(mapper.writer(prettyPrinter).writeValueAsString(actual));
        }
    }


}
