package cryptografy.symmetric;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;

import cryptografy.algorithm.SymmetricAlgorithm;

/**
 * Implementa o uso do algoritmo RC4.
 */
public class RC4Crypt extends SymmetricCrypterImpl {
    /**
     * Indica o Algoritmo implementado
     */
    public static final SymmetricAlgorithm ALGORITHM = SymmetricAlgorithm.RC4;

    /**
     * Cria uma nova instancia de RC4Crypt, com a chave especificada.
     * 
     * @param key
     *            - Chave a ser utilizada
     * @throws InvalidKeyException
     * @throws InvalidKeySpecException
     */
    public RC4Crypt(byte[] key) throws InvalidKeyException, InvalidKeySpecException {
	super(ALGORITHM, key);
    }

    /**
     * Cria uma nova instancia de RC4Crypt, com a chave especificada.
     * 
     * @param key
     *            - Chave a ser utilizada
     * @throws InvalidKeyException
     * @throws InvalidKeySpecException
     */
    public RC4Crypt(String key) throws InvalidKeyException, InvalidKeySpecException, IOException {
	super(ALGORITHM, key);
    }

    /**
     * Cria uma nova instancia de RC4Crypt, com a chave gerada no momento da construção.
     * 
     */
    public RC4Crypt() {
	super(ALGORITHM);
    }
}
