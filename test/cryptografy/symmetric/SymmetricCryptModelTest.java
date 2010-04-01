package cryptografy.symmetric;

import java.util.Arrays;
import junit.framework.TestCase;
import cryptografy.algorithm.SymmetricAlgorithm;

public abstract class SymmetricCryptModelTest extends TestCase {
    protected static String ALPHA_NUMBER_DATA = "abcdefghijklmnopkrstuvwxyz0123456789c„·È‡¸∫";
    protected static String NEW_LINE = "\n";
    protected static byte[] BYTE_ARRAY_DATA = ALPHA_NUMBER_DATA.getBytes();

    public void testGetAESCrypt() throws Throwable {
	System.out.format("TestMethod: %s.%s%s", this.getClass().getSimpleName(), "testGetAESCrypt", NEW_LINE);
	assertUsingTheAltorithm(SymmetricAlgorithm.AES);
    }

    public void testGetBlowfishCrypt() throws Throwable {
	System.out.format("TestMethod: %s.%s%s", this.getClass().getSimpleName(), "testGetBlowfishCrypt", NEW_LINE);
	assertUsingTheAltorithm(SymmetricAlgorithm.Blowfish);
    }

    public void testGetDESCrypt() throws Throwable {
	System.out.format("TestMethod: %s.%s%s", this.getClass().getSimpleName(), "testGetDESCrypt", NEW_LINE);
	assertUsingTheAltorithm(SymmetricAlgorithm.DES);
    }

    public void testGetDESedeCrypt() throws Throwable {
	System.out.format("TestMethod: %s.%s%s", this.getClass().getSimpleName(), "testGetDESedeCrypt", NEW_LINE);
	assertUsingTheAltorithm(SymmetricAlgorithm.DESede);
    }

    public void testGetPBEWithSHA1AndDESedeCrypt() throws Throwable {
	System.out.format("TestMethod: %s.%s%s", this.getClass().getSimpleName(), "testGetPBEWithSHA1AndDESedeCrypt", NEW_LINE);
	assertUsingTheAltorithm(SymmetricAlgorithm.PBEWithSHA1AndDESede);
    }

    public void testGetPBEWithMD5AndDESCrypt() throws Throwable {
	System.out.format("TestMethod: %s.%s%s", this.getClass().getSimpleName(), "testGetPBEWithMD5AndDESCrypt", NEW_LINE);
	assertUsingTheAltorithm(SymmetricAlgorithm.PBEWithMD5AndDES);
    }

    public void testGetRC2Crypt() throws Throwable {
	System.out.format("TestMethod: %s.%s%s", this.getClass().getSimpleName(), "testGetRC2Crypt", NEW_LINE);
	assertUsingTheAltorithm(SymmetricAlgorithm.RC2);
    }

    public void testGetRC4Crypt() throws Throwable {
	System.out.format("TestMethod: %s.%s%s", this.getClass().getSimpleName(), "testGetRC4Crypt", NEW_LINE);
	assertUsingTheAltorithm(SymmetricAlgorithm.RC4);
    }

    protected abstract void assertUsingTheAltorithm(SymmetricAlgorithm a) throws Throwable;

    protected void assertEquals(final byte[] expected, final byte[] actual) {
	assertTrue(Arrays.equals(expected, actual));
    }
}