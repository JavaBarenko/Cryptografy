package cryptografy.symmetric;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;

import cryptografy.algorithm.SymmetricAlgorithm;

/**
 * Implementa o uso do algoritmo DESede.
 */
public class DESedeCrypt extends SymmetricCrypterImpl {
    /**
     * Indica o Algoritmo implementado
     */
    public static final SymmetricAlgorithm ALGORITHM = SymmetricAlgorithm.DESede;

    /**
     * Cria uma nova instancia de DESedeCrypt, com a chave especificada.
     * 
     * @param key
     *            - Chave a ser utilizada
     * @throws InvalidKeyException
     * @throws InvalidKeySpecException
     */
    public DESedeCrypt(byte[] key) throws InvalidKeyException, InvalidKeySpecException {
	super(ALGORITHM, key);
    }

    /**
     * Cria uma nova instancia de DESedeCrypt, com a chave especificada.
     * 
     * @param key
     *            - Chave a ser utilizada
     * @throws InvalidKeyException
     * @throws InvalidKeySpecException
     */
    public DESedeCrypt(String key) throws InvalidKeyException, InvalidKeySpecException, IOException {
	super(ALGORITHM, key);
    }

    /**
     * Cria uma nova instancia de DESedeCrypt, com a chave gerada no momento da construção.
     * 
     */
    public DESedeCrypt() {
	super(ALGORITHM);
    }
}
