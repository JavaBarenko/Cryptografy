package cryptografy.symmetric;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
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
 */
public abstract class SymmetricCrypterImpl implements SymmetricCrypter {
    private static BASE64Encoder encoder = new BASE64Encoder();
    private static BASE64Decoder decoder = new BASE64Decoder();
    protected Cipher cipher = null;
    protected Key key = null;
    protected SymmetricAlgorithm algorithm = null;

    public SymmetricCrypterImpl(final SymmetricAlgorithm algorithm) {
	init(algorithm);
    }

    public SymmetricCrypterImpl(final SymmetricAlgorithm algorithm, final String serializedKey) throws IOException, ClassNotFoundException {
	init(algorithm);
	loadKey(decoder.decodeBuffer(serializedKey));
    }

    public SymmetricCrypterImpl(final SymmetricAlgorithm algorithm, final byte[] serializedKey) throws IOException, ClassNotFoundException {
	init(algorithm);
	loadKey(serializedKey);
    }

    private void init(final SymmetricAlgorithm algorithm) {
	this.algorithm = algorithm;
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

    public byte[] getSerializedKey() {
	return serializeKey(this.key);
    }

    public final byte[] serializeKey(final Key key) {
	ByteArrayOutputStream baos = null;
	ObjectOutputStream oos = null;
	try {
	    baos = new ByteArrayOutputStream();
	    oos = new ObjectOutputStream(baos);
	    oos.writeObject(key);
	    oos.flush();
	    return baos.toByteArray();
	} catch (final IOException e) {
	    e.printStackTrace();
	} finally {
	    if (baos != null) try {
		baos.close();
	    } catch (final IOException e) {
		e.printStackTrace();
	    }
	    if (oos != null) try {
		oos.close();
	    } catch (final IOException e) {
		e.printStackTrace();
	    }
	}
	return null;
    }

    public final Key deserializeKey(final byte[] serializedKey) throws IOException, ClassNotFoundException {
	if (serializedKey == null) return null;
	ObjectInputStream keyOis = null;
	try {
	    keyOis = new ObjectInputStream(new ByteArrayInputStream(serializedKey));
	    return (Key) keyOis.readObject();
	} finally {
	    if (keyOis != null) keyOis.close();
	}
    }

    public final void generateKey() throws InvalidKeyException, InvalidKeySpecException {
	try {
	    if (this.key == null) {
		try {
		    this.key = KeyGenerator.getInstance(this.algorithm.getAlgorithm()).generateKey();
		} catch (final NoSuchAlgorithmException e) {
		    this.key = customizedKeyGenerator();
		}
	    }
	    this.key = new SecretKeySpec(this.key.getEncoded(), this.algorithm.getAlgorithm());
	} catch (final NoSuchAlgorithmException e) {
	    e.printStackTrace();
	}
    }

    public final void loadKey(final byte[] serializedKey) throws IOException, ClassNotFoundException {
	this.key = deserializeKey(serializedKey);
    }

    @SuppressWarnings("unused")
    protected Key customizedKeyGenerator() throws NoSuchAlgorithmException {
	return null;
    }

    public SymmetricAlgorithm getAlgorithm() {
	return this.algorithm;
    }
}
