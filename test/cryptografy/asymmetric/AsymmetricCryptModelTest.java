package cryptografy.asymmetric;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import junit.framework.TestCase;
import cryptografy.CryptFactory;
import cryptografy.algorithm.AsymmetricAlgorithm;

public abstract class AsymmetricCryptModelTest extends TestCase {
    protected static String ALPHA_NUMBER_DATA = "abcdefghijklmnopkrstuvwxyz0123456789";
    protected static String NEW_LINE = "\n";

    protected static byte[] BYTE_ARRAY_DATA = ALPHA_NUMBER_DATA.getBytes();

    public void testGetRSACrypt() throws Exception {
	System.out.format("TestMethod: %s.%s%s", this.getClass().getSimpleName(), "testGetRSACrypt", NEW_LINE);
	assertUsingTheAltorithm(AsymmetricAlgorithm.RSA_1024bits);
    }

    protected abstract void assertUsingTheAltorithm(AsymmetricAlgorithm a) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, SecurityException, IllegalArgumentException, InvalidKeySpecException, IOException,
    NoSuchMethodException, InstantiationException, IllegalAccessException, InvocationTargetException, ClassNotFoundException;

    protected void assertEquals(final byte[] expected, final byte[] actual) {
	assertEquals(true, Arrays.equals(expected, actual));
    }

    protected String encriptAndDecript(final AsymmetricCrypter crypt, final String i) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException {
	final String[] encripted = crypt.encrypt(i);
	return crypt.decrypt(encripted[0], encripted[1]);
    }

    protected byte[] encriptAndDecript(final AsymmetricCrypter crypt, final byte[] i) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
	final byte[][] encripted = crypt.encrypt(i);
	return crypt.decrypt(encripted[0], encripted[1]);
    }

    protected AsymmetricCrypter usingTheCryptografy(final AsymmetricAlgorithm a) throws SecurityException, IllegalArgumentException, NoSuchMethodException, InstantiationException, IllegalAccessException, InvocationTargetException {
	final AsymmetricCryptFactory acf = AsymmetricCryptFactory.getInstance();
	return acf.getCryptografy(a);
    }

    protected KeyPair useANewKeyOf(final AsymmetricAlgorithm a) throws InvalidKeyException, InvalidKeySpecException, SecurityException, IllegalArgumentException, NoSuchMethodException, InstantiationException, IllegalAccessException,
    InvocationTargetException, IOException, ClassNotFoundException {
	return usingTheCryptografy(a).generateKeys();
    }

    protected AsymmetricCrypter usingTheCryptografy(final AsymmetricAlgorithm a, final KeyPair keys) throws SecurityException, IllegalArgumentException, NoSuchMethodException, InstantiationException, IllegalAccessException, InvocationTargetException {
	return usingTheCryptografy(a, keys.getPublic(), keys.getPrivate());
    }

    protected AsymmetricCrypter usingTheCryptografy(final AsymmetricAlgorithm a, final Object publicKey, final Object privateKey) throws SecurityException, IllegalArgumentException, NoSuchMethodException, InstantiationException, IllegalAccessException,
    InvocationTargetException {
	final AsymmetricCryptFactory acf = CryptFactory.asymmetric();
	if (publicKey instanceof String && privateKey instanceof String) {
	    return acf.getCryptografy(a, (String) publicKey, (String) privateKey);
	} else if (publicKey instanceof byte[] && privateKey instanceof byte[]) {
	    return acf.getCryptografy(a, (byte[]) publicKey, (byte[]) privateKey);
	} else if (publicKey instanceof Key && privateKey instanceof Key) {
	    final AsymmetricCrypter t = acf.getCryptografy(a);

	    return acf.getCryptografy(a, t.serializeKey((Key) publicKey), t.serializeKey((Key) privateKey));
	} else return null;
    }

}
