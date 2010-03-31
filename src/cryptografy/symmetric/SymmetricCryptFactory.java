package cryptografy.symmetric;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import cryptografy.algorithm.SymmetricAlgorithm;

/**
 * F�brica de criptografias sim�tricas. Retorna a Criptografia sim�trica escolhida.
 *
 * @author Rafael Caetano Pinto
 *
 */
public class SymmetricCryptFactory {
    private static SymmetricCryptFactory symmetricCryptFactory = new SymmetricCryptFactory();
    private static final String SYMMETRIC_CRYPT_PATTERN = "cryptografy.symmetric.%sCrypt";

    /**
     * Obt�m a f�brica de criptografias sim�tricas
     *
     * @return a f�brica de criptografias sim�tricas
     */
    public static SymmetricCryptFactory getInstance() {
	return symmetricCryptFactory;
    }

    private SymmetricCryptFactory() {
    }

    /**
     * Instancia e retorna uma implementa��o da criptografia sim�trica especificada. <br>
     * A chave ser� gerada automaticamente.
     *
     * @param algorithm
     *            - Algoritmo sim�trico
     * @return A implementa��o da criptografia escolhida
     * @throws SecurityException
     * @throws NoSuchMethodException
     * @throws IllegalArgumentException
     * @throws InstantiationException
     * @throws IllegalAccessException
     * @throws InvocationTargetException
     */
    public SymmetricCrypter getCryptografy(final SymmetricAlgorithm algorithm) throws SecurityException, NoSuchMethodException, IllegalArgumentException, InstantiationException, IllegalAccessException, InvocationTargetException {
	return getCryptClass(algorithm).newInstance();
    }

    /**
     * Instancia e retorna uma implementa��o da criptografia sim�trica especificada. <br>
     * Ser� utilizada a chave especificada.
     *
     * @param algorithm
     *            - Algoritmo sim�trico
     * @param key
     *            - Chave utilizada na criptografia
     * @return A implementa��o da criptografia escolhida
     * @throws SecurityException
     * @throws NoSuchMethodException
     * @throws IllegalArgumentException
     * @throws InstantiationException
     * @throws IllegalAccessException
     * @throws InvocationTargetException
     */
    public SymmetricCrypter getCryptografy(final SymmetricAlgorithm algorithm, final byte[] key) throws SecurityException, NoSuchMethodException, IllegalArgumentException, InstantiationException, IllegalAccessException, InvocationTargetException {
	return getCryptInstance(algorithm, key);
    }

    /**
     * Instancia e retorna uma implementa��o da criptografia sim�trica especificada. <br>
     * Ser� utilizada a chave especificada.
     *
     * @param algorithm
     *            - Algoritmo sim�trico
     * @param key
     *            - Chave utilizada na criptografia
     * @return A implementa��o da criptografia escolhida
     * @throws SecurityException
     * @throws NoSuchMethodException
     * @throws IllegalArgumentException
     * @throws InstantiationException
     * @throws IllegalAccessException
     * @throws InvocationTargetException
     */
    public SymmetricCrypter getCryptografy(final SymmetricAlgorithm algorithm, final String key) throws SecurityException, NoSuchMethodException, IllegalArgumentException, InstantiationException, IllegalAccessException, InvocationTargetException {
	return getCryptInstance(algorithm, key);
    }

    private SymmetricCrypter getCryptInstance(final SymmetricAlgorithm algorithm, final Object key) throws IllegalArgumentException, InstantiationException, IllegalAccessException, InvocationTargetException, SecurityException, NoSuchMethodException {
	final Class<SymmetricCrypter> crypt = getCryptClass(algorithm);
	final Constructor<SymmetricCrypter> cryptConstructor = crypt.getDeclaredConstructor(key.getClass());
	return cryptConstructor.newInstance(key);
    }

    @SuppressWarnings("unchecked")
    private Class<SymmetricCrypter> getCryptClass(final SymmetricAlgorithm algorithm) {
	try {
	    return (Class<SymmetricCrypter>) Class.forName(String.format(SYMMETRIC_CRYPT_PATTERN, algorithm.getAlgorithm()));
	} catch (final ClassNotFoundException e) {
	    e.printStackTrace();
	    return null;
	}
    }
}
