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
    public RC2Crypt(byte[] key) throws InvalidKeyException, InvalidKeySpecException {
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
    public RC2Crypt(String key) throws InvalidKeyException, InvalidKeySpecException, IOException {
	super(ALGORITHM, key);
    }

    /**
     * Cria uma nova instancia de RC2Crypt, com a chave gerada no momento da constru��o.
     * 
     */
    public RC2Crypt() {
	super(ALGORITHM);
    }
}
