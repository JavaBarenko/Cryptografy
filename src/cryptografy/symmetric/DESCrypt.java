package cryptografy.symmetric;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;

import cryptografy.algorithm.SymmetricAlgorithm;

/**
 * Implementa o uso do algoritmo DES.
 * */
public class DESCrypt extends SymmetricCrypterImpl {
    /**
     * Indica o Algoritmo implementado
     */
    public static final SymmetricAlgorithm ALGORITHM = SymmetricAlgorithm.DES;

    /**
     * Cria uma nova instancia de DESCrypt, com a chave especificada.
     * 
     * @param key
     *            - Chave a ser utilizada
     * @throws InvalidKeyException
     * @throws InvalidKeySpecException
     */
    public DESCrypt(byte[] key) throws InvalidKeyException, InvalidKeySpecException {
	super(ALGORITHM, key);
    }

    /**
     * Cria uma nova instancia de DESCrypt, com a chave especificada.
     * 
     * @param key
     *            - Chave a ser utilizada
     * @throws InvalidKeyException
     * @throws InvalidKeySpecException
     */
    public DESCrypt(String key) throws InvalidKeyException, InvalidKeySpecException, IOException {
	super(ALGORITHM, key);
    }

    /**
     * Cria uma nova instancia de DESCrypt, com a chave gerada no momento da construção.
     * 
     */
    public DESCrypt() {
	super(ALGORITHM);
    }
}
