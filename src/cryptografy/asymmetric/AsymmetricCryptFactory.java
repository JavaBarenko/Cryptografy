package cryptografy.asymmetric;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import cryptografy.algorithm.AsymmetricAlgorithm;

/**
 * Fábrica de criptografias assimétricas. Retorna a Criptografia assimétrica escolhida.
 * 
 * @author Rafael Caetano Pinto
 */
public class AsymmetricCryptFactory {
    private static AsymmetricCryptFactory asymmetricCryptFactory = new AsymmetricCryptFactory();
    private static final String ASYMMETRIC_CRYPT_PATTERN = "cryptografy.asymmetric.%sCrypt";

    /**
     * Obtém a fábrica de criptografias assimétricas
     * 
     * @return a fábrica de criptografias assimétricas
     */
    public static AsymmetricCryptFactory getInstance() {
	return asymmetricCryptFactory;
    }

    private AsymmetricCryptFactory() {}

    /**
     * Instancia e retorna uma implementação da criptografia assimétrica especificada. <br>
     * As chaves publica e privada serão geradas automaticamente.
     * 
     * @param algorithm
     *            - Algoritmo assimétrico
     * @return A implementação da criptografia escolhida
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
     * Instancia e retorna uma implementação da criptografia assimétrica especificada. <br>
     * As chaves publica e privada serão geradas automaticamente caso ambas sejam nulas.
     * 
     * @param algorithm
     *            - Algoritmo assimétrico
     * @param serializedPublicKey
     *            - Chave publica serializada
     * @param serializedPrivateKey
     *            - Chave privada serializada
     * @return A implementação da criptografia escolhida
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
     * Instancia e retorna uma implementação da criptografia assimétrica especificada. <br>
     * As chaves publica e privada serão geradas automaticamente caso ambas sejam nulas.
     * 
     * @param algorithm
     *            - Algoritmo assimétrico
     * @param serializedPublicKey
     *            - Chave publica serializada
     * @param serializedPrivateKey
     *            - Chave privada serializada
     * @return A implementação da criptografia escolhida
     * @throws SecurityException
     * @throws NoSuchMethodException
     * @throws IllegalArgumentException
     * @throws InstantiationException
     * @throws IllegalAccessException
     * @throws InvocationTargetException
     */
    public AsymmetricCrypter getCryptografy(final AsymmetricAlgorithm algorithm, final String serializedPublicKey, final String serializedPrivateKey) throws SecurityException, NoSuchMethodException, IllegalArgumentException, InstantiationException,
    IllegalAccessException, InvocationTargetException {
	return getCryptInstance(algorithm, serializedPublicKey, serializedPrivateKey);
    }

    private AsymmetricCrypter getCryptInstance(final AsymmetricAlgorithm algorithm, final Object publicKey, final Object privateKey) throws IllegalArgumentException, InstantiationException, IllegalAccessException, InvocationTargetException,
    SecurityException, NoSuchMethodException {
	final Class<AsymmetricCrypter> crypt = getCryptClass(algorithm);
	final Constructor<AsymmetricCrypter> cryptConstructor = crypt.getDeclaredConstructor(publicKey.getClass(), privateKey.getClass());
	return cryptConstructor.newInstance(publicKey, privateKey);
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
