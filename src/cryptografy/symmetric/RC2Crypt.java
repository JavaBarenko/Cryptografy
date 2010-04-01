package cryptografy.symmetric;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import cryptografy.algorithm.SymmetricAlgorithm;

/**
 * Implementa o uso do algoritmo RC2.
 */
public class RC2Crypt extends SymmetricCrypterImpl {
    /**
     * Indica o Algoritmo implementado
     */
    public static final SymmetricAlgorithm ALGORITHM = SymmetricAlgorithm.RC2;

    /**
     * Cria uma nova instancia de RC2Crypt, com a chave especificada.
     * 
     * @param key
     *            - Chave a ser utilizada
     * @throws InvalidKeyException
     * @throws InvalidKeySpecException
     */
    public RC2Crypt(final byte[] key) throws IOException, ClassNotFoundException {
	super(ALGORITHM, key);
    }

    /**
     * Cria uma nova instancia de RC2Crypt, com a chave especificada.
     * 
     * @param key
     *            - Chave a ser utilizada
     * @throws InvalidKeyException
     * @throws InvalidKeySpecException
     */
    public RC2Crypt(final String key) throws IOException, ClassNotFoundException {
	super(ALGORITHM, key);
    }

    /**
     * Cria uma nova instancia de RC2Crypt, com a chave gerada no momento da construção.
     * 
     */
    public RC2Crypt() {
	super(ALGORITHM);
    }
}
