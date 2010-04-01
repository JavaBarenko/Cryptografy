package cryptografy.asymmetric;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.security.KeyPair;
import cryptografy.algorithm.AsymmetricAlgorithm;

/**
 * F�brica de criptografias assim�tricas. Retorna a Criptografia assim�trica escolhida.
 * 
 * @author Rafael Caetano Pinto
 */
public class AsymmetricCryptFactory {
    private static AsymmetricCryptFactory asymmetricCryptFactory = new AsymmetricCryptFactory();
    private static final String ASYMMETRIC_CRYPT_PATTERN = "cryptografy.asymmetric.%sCrypt";

    /**
     * Obt�m a f�brica de criptografias assim�tricas
     * 
     * @return a f�brica de criptografias assim�tricas
     */
    public static AsymmetricCryptFactory getInstance() {
	return asymmetricCryptFactory;
    }

    private AsymmetricCryptFactory() {}

    /**
     * Instancia e retorna uma implementa��o da criptografia assim�trica especificada. <br>
     * As chaves publica e privada ser�o geradas automaticamente.
     * 
     * @param algorithm
     *            - Algoritmo assim�trico
     * @return A implementa��o da criptografia escolhida
     * @throws SecurityException
     * @throws NoSuchMethodException
     * @throws IllegalArgumentException
     * @throws InstantiationException
     * @throws IllegalAccessException
     * @throws InvocationTargetException
     */
    public AsymmetricCrypter getCryptografy(final AsymmetricAlgorithm algorithm) throws SecurityException, NoSuchMethodException, IllegalArgumentException, InstantiationException, IllegalAccessException, InvocationTargetException {
	return getCryptClass(algorithm).newInstance();
    }

    /**
     * Instancia e retorna uma implementa��o da criptografia assim�trica especificada. <br>
     * As chaves publica e privada ser�o geradas automaticamente caso ambas sejam nulas.
     * 
     * @param algorithm
     *            - Algoritmo assim�trico
     * @param serializedPublicKey
     *            - Chave publica serializada
     * @param serializedPrivateKey
     *            - Chave privada serializada
     * @return A implementa��o da criptografia escolhida
     * @throws SecurityException
     * @throws NoSuchMethodException
     * @throws IllegalArgumentException
     * @throws InstantiationException
     * @throws IllegalAccessException
     * @throws InvocationTargetException
     */
    public AsymmetricCrypter getCryptografy(final AsymmetricAlgorithm algorithm, final KeyPair keys) throws SecurityException, NoSuchMethodException, IllegalArgumentException, InstantiationException,
    IllegalAccessException, InvocationTargetException {
	return getCryptInstance(algorithm, keys);
    }

    /**
     * Instancia e retorna uma implementa��o da criptografia assim�trica especificada. <br>
     * As chaves publica e privada ser�o geradas automaticamente caso ambas sejam nulas.
     * 
     * @param algorithm
     *            - Algoritmo assim�trico
     * @param serializedPublicKey
     *            - Chave publica serializada
     * @param serializedPrivateKey
     *            - Chave privada serializada
     * @return A implementa��o da criptografia escolhida
     * @throws SecurityException
     * @throws NoSuchMethodException
     * @throws IllegalArgumentException
     * @throws InstantiationException
     * @throws IllegalAccessException
     * @throws InvocationTargetException
     */
    public AsymmetricCrypter getCryptografy(final AsymmetricAlgorithm algorithm, final byte[] serializedPublicKey, final byte[] serializedPrivateKey) throws SecurityException, NoSuchMethodException, IllegalArgumentException, InstantiationException,
		IllegalAccessException, InvocationTargetException {
	return getCryptInstance(algorithm, serializedPublicKey, serializedPrivateKey);
    }

    /**
     * Instancia e retorna uma implementa��o da criptografia assim�trica especificada. <br>
     * As chaves publica e privada ser�o geradas automaticamente caso ambas sejam nulas.
     * 
     * @param algorithm
     *            - Algoritmo assim�trico
     * @param serializedPublicKey
     *            - Chave publica serializada
     * @param serializedPrivateKey
     *            - Chave privada serializada
     * @return A implementa��o da criptografia escolhida
     * @throws SecurityException
     * @throws NoSuchMethodException
     * @throws IllegalArgumentException
     * @throws InstantiationException
     * @throws IllegalAccessException
     * @throws InvocationTargetException
     */
    public AsymmetricCrypter getCryptografy(final AsymmetricAlgorithm algorithm, final byte[] serializedPublicKey) throws SecurityException, NoSuchMethodException, IllegalArgumentException, InstantiationException, IllegalAccessException,
		InvocationTargetException {
	return getCryptInstance(algorithm, serializedPublicKey, null);
    }

    private AsymmetricCrypter getCryptInstance(final AsymmetricAlgorithm algorithm, final KeyPair keys) throws IllegalArgumentException, InstantiationException, IllegalAccessException, InvocationTargetException,
    SecurityException, NoSuchMethodException {
	final Class<AsymmetricCrypter> crypt = getCryptClass(algorithm);
	final Constructor<AsymmetricCrypter> cryptConstructor = crypt.getDeclaredConstructor(KeyPair.class);
	return cryptConstructor.newInstance(keys);
    }

    private AsymmetricCrypter getCryptInstance(final AsymmetricAlgorithm algorithm, final byte[] serializedPublicKey, final byte[] serializedPrivateKey) throws IllegalArgumentException, InstantiationException, IllegalAccessException,
		InvocationTargetException, SecurityException, NoSuchMethodException {
	final Class<AsymmetricCrypter> crypt = getCryptClass(algorithm);
	final Constructor<AsymmetricCrypter> cryptConstructor = crypt.getDeclaredConstructor(byte[].class, byte[].class);
	return cryptConstructor.newInstance(serializedPublicKey, serializedPrivateKey);
    }

    @SuppressWarnings("unchecked")
    private Class<AsymmetricCrypter> getCryptClass(final AsymmetricAlgorithm algorithm) {
	try {
	    return (Class<AsymmetricCrypter>) Class.forName(String.format(ASYMMETRIC_CRYPT_PATTERN, algorithm.getAlgorithm()));
	} catch (final ClassNotFoundException e) {
	    e.printStackTrace();
	    return null;
	}
    }
}
