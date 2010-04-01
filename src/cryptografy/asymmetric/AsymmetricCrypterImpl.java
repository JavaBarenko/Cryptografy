package cryptografy.asymmetric;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import sun.misc.BASE64Decoder;
import cryptografy.algorithm.AsymmetricAlgorithm;
import cryptografy.algorithm.SymmetricAlgorithm;

/**
 * Classe modelo de implementação de criptografias assimétricas. <br>
 * Essa classe é utilizada como base para qualquer outra especialização de criptografias assimétricas.
 * 
 * @author Rafael Caetano Pinto
 */
public abstract class AsymmetricCrypterImpl implements AsymmetricCrypter {
    private static BASE64Decoder decoder = new BASE64Decoder();
    protected Cipher cipher = null;
    protected KeyPair keys = null;
    protected AsymmetricAlgorithm algorithm = null;

    /**
     * Algoritmo utilizado para a criptografia simétrica da mensagem. <br>
     * Ele permite os seguintes valores, sempre respeitando a capacidade do algorítmo simétrico (encryptKeyAlgorithm) e
     * do algoritmo assimétrico escolhidos. <br>
     * <br>
     * AES/CBC/NoPadding (128) <br>
     * AES/CBC/PKCS5Padding (128) <br>
     * AES/ECB/NoPadding (128) <br>
     * AES/ECB/PKCS5Padding (128) <br>
     * DES/CBC/NoPadding (56) <br>
     * DES/CBC/PKCS5Padding (56) <br>
     * DES/ECB/NoPadding (56) <br>
     * DES/ECB/PKCS5Padding (56) <br>
     * DESede/CBC/NoPadding (168) <br>
     * DESede/CBC/PKCS5Padding (168) <br>
     * DESede/ECB/NoPadding (168) <br>
     * DESede/ECB/PKCS5Padding (168) <br>
     * RSA/ECB/PKCS1Padding (2048) <br>
     * RSA/ECB/OAEPPadding (2048)
     */
    protected String encryptSymmetricMessageKeyAlgorithm = "AES/CBC/PKCS5Padding";
    protected SymmetricAlgorithm encryptKeyAlgorithm = SymmetricAlgorithm.AES;
    protected int encryptKeyAlgorithmKeysize = 128;

    public AsymmetricCrypterImpl(final AsymmetricAlgorithm algorithm) {
	init(algorithm, null, null);
    }

    public AsymmetricCrypterImpl(final AsymmetricAlgorithm algorithm, final KeyPair keys) {
	init(algorithm, null, null);
    }

    public AsymmetricCrypterImpl(final AsymmetricAlgorithm algorithm, final byte[] serializedPublicKey, final byte[] serializedPrivateKey) throws IOException, ClassNotFoundException {
	init(algorithm, null, null);
	loadKeys(serializedPublicKey, serializedPrivateKey);
    }

    public AsymmetricCrypterImpl(final AsymmetricAlgorithm algorithm, final byte[] serializedPublicKey) throws IOException, ClassNotFoundException {
	init(algorithm, null, null);
	loadKeys(serializedPublicKey, null);
    }

    public AsymmetricCrypterImpl(final AsymmetricAlgorithm algorithm, final SymmetricAlgorithm encryptKeyAlgorithm, final int encryptKeyAlgorithmKeysize) {
	init(algorithm, encryptKeyAlgorithm, encryptKeyAlgorithmKeysize);
    }


    private void init(final AsymmetricAlgorithm algorithm, final SymmetricAlgorithm encryptKeyAlgorithm, final Integer encryptKeyAlgorithmKeysize) {
	this.algorithm = algorithm;

	if (encryptKeyAlgorithm != null) this.encryptKeyAlgorithm = encryptKeyAlgorithm;
	if (encryptKeyAlgorithmKeysize != null) this.encryptKeyAlgorithmKeysize = encryptKeyAlgorithmKeysize;

	try {
	    this.cipher = Cipher.getInstance(algorithm.getAlgorithm());

	} catch (final NoSuchAlgorithmException e) {
	    e.printStackTrace();
	} catch (final NoSuchPaddingException e) {
	    e.printStackTrace();
	}
    }

    public AsymmetricAlgorithm getAlgorithm() {
	return this.algorithm;
    }

    protected byte[] generateEncryptSymmetricKey() {
	KeyGenerator kg;
	try {
	    kg = KeyGenerator.getInstance(this.encryptKeyAlgorithm.getAlgorithm());
	    kg.init(this.encryptKeyAlgorithmKeysize);
	    final SecretKey sk = kg.generateKey();
	    return sk.getEncoded();
	} catch (final NoSuchAlgorithmException e) {
	    e.printStackTrace();
	    return null;
	}
    }

    public final EncryptSet encrypt(final byte[] input) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
	Cipher aescf;
	try {
	    aescf = Cipher.getInstance(this.encryptSymmetricMessageKeyAlgorithm);
	    final IvParameterSpec ivspec = new IvParameterSpec(new byte[16]);
	    final byte[] symmetricKey = generateEncryptSymmetricKey();
	    aescf.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(symmetricKey, this.encryptKeyAlgorithm.getAlgorithm()), ivspec);
	    final byte[] encryptedInput = aescf.doFinal(input);

	    this.cipher.init(Cipher.ENCRYPT_MODE, this.keys.getPrivate());
	    final byte[] encryptedKey = this.cipher.doFinal(symmetricKey);

	    return new EncryptSet(encryptedInput, encryptedKey, this.keys.getPublic());
	} catch (final NoSuchAlgorithmException e) {
	    e.printStackTrace();
	} catch (final NoSuchPaddingException e) {
	    e.printStackTrace();
	} catch (final InvalidAlgorithmParameterException e) {
	    e.printStackTrace();
	}
	return null;
    }

    public final byte[] decrypt(final byte[] input, final byte[] encryptedKey) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
	Cipher aescf;
	try {
	    this.cipher.init(Cipher.DECRYPT_MODE, this.keys.getPublic());
	    final byte[] decryptedKey = this.cipher.doFinal(encryptedKey);
	    aescf = Cipher.getInstance(this.encryptSymmetricMessageKeyAlgorithm);
	    final IvParameterSpec ivspec = new IvParameterSpec(new byte[16]);

	    aescf.init(Cipher.DECRYPT_MODE, new SecretKeySpec(decryptedKey, this.encryptKeyAlgorithm.getAlgorithm()), ivspec);
	    return aescf.doFinal(input);
	} catch (final NoSuchAlgorithmException e) {
	    e.printStackTrace();
	} catch (final NoSuchPaddingException e) {
	    e.printStackTrace();
	} catch (final InvalidAlgorithmParameterException e) {
	    e.printStackTrace();
	}
	return null;

    }

    public final EncryptSet encrypt(final String input) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException {
	return encrypt(input.getBytes());
    }

    public final String decrypt(final String input, final String encryptedKey) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException {
	final byte[] result = decrypt(decoder.decodeBuffer(input), decoder.decodeBuffer(encryptedKey));
	return new String(result);
    }

    public final KeyPair getKeys() {
	return this.keys;
    }

    public final byte[] getSerializableKeys() {
	final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
	ObjectOutputStream oos = null;
	try {
	    oos = new ObjectOutputStream(byteArrayOutputStream);
	    final Serializable s = this.keys;
	    oos.writeObject(s);
	} catch (final IOException e) {
	    e.printStackTrace();
	} finally {
	    try {
		oos.close();
	    } catch (final IOException e) {}
	}
	return byteArrayOutputStream.toByteArray();
    }

    public final byte[] getSerializablePublicKey() {
	final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
	ObjectOutputStream oos = null;
	try {
	    oos = new ObjectOutputStream(byteArrayOutputStream);
	    final Serializable s = this.keys.getPublic();
	    oos.writeObject(s);
	} catch (final IOException e) {
	    e.printStackTrace();
	} finally {
	    try {
		oos.close();
	    } catch (final IOException e) {}
	}
	return byteArrayOutputStream.toByteArray();
    }

    public final byte[] getSerializedPublicKey() {
	return serializeKey(this.keys.getPublic());
    }

    public final byte[] getSerializedPrivateKey() {
	return serializeKey(this.keys.getPrivate());
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

    public final void generateKeys() throws InvalidKeyException, InvalidKeySpecException, IOException, ClassNotFoundException {
	try {
	    final KeyPairGenerator kpg = KeyPairGenerator.getInstance(this.algorithm.getAlgorithm());
	    try {
		kpg.initialize(getAlgorithmParameterSpec());
	    } catch (final InvalidAlgorithmParameterException e) {
		e.printStackTrace();
	    }
	    this.keys = kpg.generateKeyPair();
	} catch (final NoSuchAlgorithmException e) {
	    try {
		this.keys = KeyPairGenerator.getInstance(this.algorithm.getAlgorithm()).generateKeyPair();
	    } catch (final NoSuchAlgorithmException e1) {
		e.printStackTrace();
	    }
	}
    }

    public void loadKeys(final byte[] serializedPublicKey, final byte[] serializedPrivateKey) throws IOException, ClassNotFoundException {
	final PublicKey pub = (PublicKey) deserializeKey(serializedPublicKey);
	final PrivateKey priv = (PrivateKey) deserializeKey(serializedPrivateKey);
	this.keys = new KeyPair(pub, priv);
    }

    protected abstract AlgorithmParameterSpec getAlgorithmParameterSpec();

    public final KeyPair deserializeKeys(final byte[] serializedKeys) throws IOException, ClassNotFoundException {
	ObjectInputStream ois = null;
	try {
	    ois = new ObjectInputStream(new ByteArrayInputStream(serializedKeys));
	    return (KeyPair) ois.readObject();
	} finally {
	    ois.close();
	}
    }

    public final PublicKey deserializePublicKey(final byte[] serializedKeys) throws IOException, ClassNotFoundException {
	ObjectInputStream ois = null;
	try {
	    ois = new ObjectInputStream(new ByteArrayInputStream(serializedKeys));
	    return (PublicKey) ois.readObject();
	} finally {
	    ois.close();
	}
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

}
