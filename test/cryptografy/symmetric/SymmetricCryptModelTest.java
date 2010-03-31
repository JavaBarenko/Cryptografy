package cryptografy.symmetric;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import junit.framework.TestCase;
import cryptografy.CryptFactory;
import cryptografy.algorithm.SymmetricAlgorithm;

public abstract class SymmetricCryptModelTest extends TestCase {
    protected static String ALPHA_NUMBER_DATA = "abcdefghijklmnopkrstuvwxyz0123456789c„·È‡¸∫";
    protected static String NEW_LINE = "\n";
    protected static byte[] BYTE_ARRAY_DATA = ALPHA_NUMBER_DATA.getBytes();

    public void testGetAESCrypt() throws Exception {
	System.out.format("TestMethod: %s.%s%s", this.getClass().getSimpleName(), "testGetAESCrypt", NEW_LINE);
	assertUsingTheAltorithm(SymmetricAlgorithm.AES);
    }

    public void testGetBlowfishCrypt() throws Exception {
	System.out.format("TestMethod: %s.%s%s", this.getClass().getSimpleName(), "testGetBlowfishCrypt", NEW_LINE);
	assertUsingTheAltorithm(SymmetricAlgorithm.Blowfish);
    }

    public void testGetDESCrypt() throws Exception {
	System.out.format("TestMethod: %s.%s%s", this.getClass().getSimpleName(), "testGetDESCrypt", NEW_LINE);
	assertUsingTheAltorithm(SymmetricAlgorithm.DES);
    }

    public void testGetDESedeCrypt() throws Exception {
	System.out.format("TestMethod: %s.%s%s", this.getClass().getSimpleName(), "testGetDESedeCrypt", NEW_LINE);
	assertUsingTheAltorithm(SymmetricAlgorithm.DESede);
    }

    public void testGetPBEWithSHA1AndDESedeCrypt() throws Exception {
	System.out.format("TestMethod: %s.%s%s", this.getClass().getSimpleName(), "testGetPBEWithSHA1AndDESedeCrypt", NEW_LINE);
	assertUsingTheAltorithm(SymmetricAlgorithm.PBEWithSHA1AndDESede);
    }

    public void testGetPBEWithMD5AndDESCrypt() throws Exception {
	System.out.format("TestMethod: %s.%s%s", this.getClass().getSimpleName(), "testGetPBEWithMD5AndDESCrypt", NEW_LINE);
	assertUsingTheAltorithm(SymmetricAlgorithm.PBEWithMD5AndDES);
    }

    public void testGetRC2Crypt() throws Exception {
	System.out.format("TestMethod: %s.%s%s", this.getClass().getSimpleName(), "testGetRC2Crypt", NEW_LINE);
	assertUsingTheAltorithm(SymmetricAlgorithm.RC2);
    }

    public void testGetRC4Crypt() throws Exception {
	System.out.format("TestMethod: %s.%s%s", this.getClass().getSimpleName(), "testGetRC4Crypt", NEW_LINE);
	assertUsingTheAltorithm(SymmetricAlgorithm.RC4);
    }

    protected abstract void assertUsingTheAltorithm(SymmetricAlgorithm a) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, SecurityException, IllegalArgumentException, InvalidKeySpecException, IOException,
    NoSuchMethodException, InstantiationException, IllegalAccessException, InvocationTargetException;

    protected String encriptAndDecript(final SymmetricCrypter crypt, final String i) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException {
	final String encripted = crypt.encrypt(i);
	return crypt.decrypt(encripted);
    }

    protected byte[] encriptAndDecript(final SymmetricCrypter crypt, final byte[] i) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
	return crypt.decrypt(crypt.encrypt(i));
    }

    protected SymmetricCrypter usingTheCryptografy(final SymmetricAlgorithm a) throws SecurityException, IllegalArgumentException, NoSuchMethodException, InstantiationException, IllegalAccessException, InvocationTargetException {
	final SymmetricCryptFactory scf = SymmetricCryptFactory.getInstance();
	return scf.getCryptografy(a);
    }

    protected Key useANewKeyOf(final SymmetricAlgorithm a) throws InvalidKeyException, InvalidKeySpecException, SecurityException, IllegalArgumentException, NoSuchMethodException, InstantiationException, IllegalAccessException,
    InvocationTargetException {
	return usingTheCryptografy(a).generateKey();
    }

    protected SymmetricCrypter usingTheCryptografy(final SymmetricAlgorithm a, final Object key) throws SecurityException, IllegalArgumentException, NoSuchMethodException, InstantiationException, IllegalAccessException, InvocationTargetException {
	final SymmetricCryptFactory scf = CryptFactory.symmetric();
	if (key instanceof String) {
	    return scf.getCryptografy(a, (String) key);
	} else if (key instanceof byte[]) {
	    return scf.getCryptografy(a, (byte[]) key);
	} else if (key instanceof Key) {
	    return scf.getCryptografy(a, ((Key) key).getEncoded());
	} else return null;
    }

    protected void assertEquals(final byte[] expected, final byte[] actual) {
	assertTrue(Arrays.equals(expected, actual));
    }
}
