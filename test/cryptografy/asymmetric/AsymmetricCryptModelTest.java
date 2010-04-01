package cryptografy.asymmetric;

import java.util.Arrays;
import junit.framework.TestCase;
import cryptografy.algorithm.AsymmetricAlgorithm;

public abstract class AsymmetricCryptModelTest extends TestCase {
    protected static String ALPHA_NUMBER_DATA = "abcdefghijklmnopkrstuvwxyz0123456789";
    protected static String NEW_LINE = "\n";

    protected static byte[] BYTE_ARRAY_DATA = ALPHA_NUMBER_DATA.getBytes();

    public void testGetRSACrypt() throws Throwable {
	System.out.format("TestMethod: %s.%s%s", this.getClass().getSimpleName(), "testGetRSACrypt", NEW_LINE);
	assertUsingTheAltorithm(AsymmetricAlgorithm.RSA_1024bits);
    }

    protected abstract void assertUsingTheAltorithm(AsymmetricAlgorithm a) throws Throwable;

    protected void assertEquals(final byte[] expected, final byte[] actual) {
	assertEquals(true, Arrays.equals(expected, actual));
    }
}