package cryptografy.symmetric;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;
import cryptografy.algorithm.SymmetricAlgorithm;

/**
 * Classe modelo de implementação de criptografias assimétricas. <br>
 * Essa classe é utilizada como base para qualquer outra especialização de criptografias assimétricas.
 *
 * @author Rafael Caetano Pinto
 *
 */
public abstract class SymmetricCrypterImpl implements SymmetricCrypter {
    private static BASE64Encoder encoder = new BASE64Encoder();
    private static BASE64Decoder decoder = new BASE64Decoder();
    protected Cipher cipher = null;
    protected Key key = null;
    protected SymmetricAlgorithm algorithm = null;

    public SymmetricCrypterImpl(final SymmetricAlgorithm algorithm) {
	try {
	    init(algorithm, null);
	} catch (final InvalidKeyException e) {
	    e.printStackTrace();
	} catch (final InvalidKeySpecException e) {
	    e.printStackTrace();
	}
    }

    public SymmetricCrypterImpl(final SymmetricAlgorithm algorithm, final String key) throws InvalidKeyException, InvalidKeySpecException, IOException {
	init(algorithm, decoder.decodeBuffer(key));
    }

    public SymmetricCrypterImpl(final SymmetricAlgorithm algorithm, final byte[] key) throws InvalidKeyException, InvalidKeySpecException {
	init(algorithm, key);
    }

    private void init(final SymmetricAlgorithm algorithm, final byte[] key) throws InvalidKeyException, InvalidKeySpecException {
	this.algorithm = algorithm;
	this.key = generateKey(key);
	try {
	    this.cipher = Cipher.getInstance(algorithm.getAlgorithm());
	} catch (final NoSuchAlgorithmException e) {
	    e.printStackTrace();
	} catch (final NoSuchPaddingException e) {
	    e.printStackTrace();
	}
    }

    protected void cipherInitConfig(final int cipherMode, final Key key) throws InvalidKeyException {
	this.cipher.init(cipherMode, key);
    }

    private byte[] crypt(final int cipherMode, final byte[] input) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
	cipherInitConfig(cipherMode, this.key);
	return this.cipher.doFinal(input);
    }

    public final byte[] encrypt(final byte[] input) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
	return crypt(Cipher.ENCRYPT_MODE, input);
    }

    public final byte[] decrypt(final byte[] input) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
	return crypt(Cipher.DECRYPT_MODE, input);
    }

    public final String encrypt(final String input) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
	return encoder.encode(encrypt(input.getBytes()));
    }

    public final String decrypt(final String input) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException {
	return new String(decrypt(decoder.decodeBuffer(input)));
    }

    public final Key getKey() {
	return this.key;
    }

    public final Key generateKey() throws InvalidKeyException, InvalidKeySpecException {
	return generateKey(null);
    }

    public final Key generateKey(final byte[] key) throws InvalidKeyException, InvalidKeySpecException {
	try {
	    if (key == null) {
		try {
		    return KeyGenerator.getInstance(this.algorithm.getAlgorithm()).generateKey();
		} catch (final NoSuchAlgorithmException e) {
		    return customizedKeyGenerator();
		}
	    }
	    return new SecretKeySpec(key, this.algorithm.getAlgorithm());
	} catch (final NoSuchAlgorithmException e) {
	    e.printStackTrace();
	    return null;
	}
    }

    @SuppressWarnings("unused")
    protected Key customizedKeyGenerator() throws NoSuchAlgorithmException {
	return null;
    }
}
