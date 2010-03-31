package cryptografy.asymmetric;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
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
import cryptografy.algorithm.AsymmetricAlgorithm;
import cryptografy.algorithm.SymmetricAlgorithm;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

/**
 * Classe modelo de implementação de criptografias assimétricas. <br>
 * Essa classe é utilizada como base para qualquer outra especialização de criptografias assimétricas.
 * 
 * @author Rafael Caetano Pinto
 */
public abstract class AsymmetricCrypterImpl implements AsymmetricCrypter {
    private static BASE64Encoder encoder = new BASE64Encoder();
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

    public AsymmetricCrypterImpl(final AsymmetricAlgorithm algorithm) throws InvalidKeyException, InvalidKeySpecException, IOException, ClassNotFoundException {
	init(algorithm, null, null, null, null);
    }

    public AsymmetricCrypterImpl(final AsymmetricAlgorithm algorithm, final byte[] serializedPublicKey, final byte[] serializedPrivateKey) throws InvalidKeyException, InvalidKeySpecException, IOException, ClassNotFoundException {
	init(algorithm, serializedPublicKey, serializedPrivateKey, null, null);
    }

    public AsymmetricCrypterImpl(final AsymmetricAlgorithm algorithm, final String serializedPublicKey, final String serializedPrivateKey) throws InvalidKeyException, InvalidKeySpecException, IOException, ClassNotFoundException {
	this(algorithm, decoder.decodeBuffer(serializedPublicKey), decoder.decodeBuffer(serializedPrivateKey));
    }

    public AsymmetricCrypterImpl(final AsymmetricAlgorithm algorithm, final String serializedPublicKey, final String serializedPrivateKey, final SymmetricAlgorithm encryptKeyAlgorithm, final int encryptKeyAlgorithmKeysize)
		throws InvalidKeyException, InvalidKeySpecException, IOException, ClassNotFoundException {
	init(algorithm, decoder.decodeBuffer(serializedPublicKey), decoder.decodeBuffer(serializedPrivateKey), encryptKeyAlgorithm, encryptKeyAlgorithmKeysize);
    }

    public AsymmetricCrypterImpl(final AsymmetricAlgorithm algorithm, final byte[] serializedPublicKey, final byte[] serializedPrivateKey, final SymmetricAlgorithm encryptKeyAlgorithm, final int encryptKeyAlgorithmKeysize)
		throws InvalidKeyException, InvalidKeySpecException, IOException, ClassNotFoundException {
	init(algorithm, serializedPublicKey, serializedPrivateKey, encryptKeyAlgorithm, encryptKeyAlgorithmKeysize);
    }

    private void init(final AsymmetricAlgorithm algorithm, final byte[] serializedPublicKey, final byte[] serializedPrivateKey, final SymmetricAlgorithm encryptKeyAlgorithm, final Integer encryptKeyAlgorithmKeysize) throws InvalidKeyException,
		InvalidKeySpecException, IOException, ClassNotFoundException {
	this.algorithm = algorithm;
	this.keys = generateKeys(serializedPublicKey, serializedPrivateKey);

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

    public final byte[][] encrypt(final byte[] input) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
	Cipher aescf;
	try {
	    aescf = Cipher.getInstance(this.encryptSymmetricMessageKeyAlgorithm);
	    final IvParameterSpec ivspec = new IvParameterSpec(new byte[16]);
	    final byte[] symmetricKey = generateEncryptSymmetricKey();
	    aescf.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(symmetricKey, this.encryptKeyAlgorithm.getAlgorithm()), ivspec);
	    final byte[] cryptedInput = aescf.doFinal(input);
	    this.cipher.init(Cipher.ENCRYPT_MODE, this.keys.getPrivate());
	    final byte[] cryptedKey = this.cipher.doFinal(symmetricKey);

	    final byte[][] result = { cryptedInput, cryptedKey };
	    return result;
	} catch (final NoSuchAlgorithmException e) {
	    e.printStackTrace();
	} catch (final NoSuchPaddingException e) {
	    e.printStackTrace();
	} catch (final InvalidAlgorithmParameterException e) {
	    e.printStackTrace();
	}
	return null;

    }

    public final byte[] decrypt(final byte[] input, final byte[] key) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
	Cipher aescf;
	try {
	    this.cipher.init(Cipher.DECRYPT_MODE, this.keys.getPublic());
	    final byte[] decryptedKey = this.cipher.doFinal(key);
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

    public final String[] encrypt(final String input) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException {
	final String[] result = new String[2];
	final byte[][] encripted = encrypt(input.getBytes());
	result[0] = encoder.encode(encripted[0]);
	result[1] = encoder.encode(encripted[1]);
	return result;
    }

    public final String decrypt(final String input, final String key) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException {
	final byte[] result = decrypt(decoder.decodeBuffer(input), decoder.decodeBuffer(key));
	return new String(result);
    }

    public final KeyPair getKeys() {
	return this.keys;
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

    public final KeyPair generateKeys() throws InvalidKeyException, InvalidKeySpecException, IOException, ClassNotFoundException {
	return generateKeys(null, null);
    }

    protected abstract AlgorithmParameterSpec getAlgorithmParameterSpec();

    public final KeyPair generateKeys(final byte[] serializedPublicKey, final byte[] serializedPrivateKey) throws InvalidKeyException, InvalidKeySpecException, IOException, ClassNotFoundException {
	try {
	    if (serializedPublicKey == null && serializedPrivateKey == null) {
		try {
		    final KeyPairGenerator kpg = KeyPairGenerator.getInstance(this.algorithm.getAlgorithm());
		    try {
			kpg.initialize(getAlgorithmParameterSpec());
		    } catch (final InvalidAlgorithmParameterException e) {
			e.printStackTrace();
			return null;
		    }
		    return kpg.generateKeyPair();
		} catch (final NoSuchAlgorithmException e) {
		    return KeyPairGenerator.getInstance(this.algorithm.getAlgorithm()).generateKeyPair();
		}
	    }

	    PublicKey pubKey = null;
	    if (serializedPublicKey != null) {
		pubKey = (PublicKey) unserializeKey(serializedPublicKey);
	    }

	    PrivateKey privKey = null;
	    if (serializedPrivateKey != null) {
		privKey = (PrivateKey) unserializeKey(serializedPrivateKey);
	    }

	    return new KeyPair(pubKey, privKey);
	} catch (final NoSuchAlgorithmException e) {
	    e.printStackTrace();
	    return null;
	}
    }

    public final Key unserializeKey(final byte[] key) throws IOException, ClassNotFoundException {
	ObjectInputStream keyOis = null;
	try {
	    keyOis = new ObjectInputStream(new ByteArrayInputStream(key));
	    return (Key) keyOis.readObject();
	} finally {
	    if (keyOis != null) keyOis.close();
	}
    }
}
