package cryptografy.symmetric;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;

import cryptografy.algorithm.SymmetricAlgorithm;

/**
 * Implementa o uso do algoritmo Blowfish.
 */
public class BlowfishCrypt extends SymmetricCrypterImpl {
    /**
     * Indica o Algoritmo implementado
     */
    public static final SymmetricAlgorithm ALGORITHM = SymmetricAlgorithm.Blowfish;

     /**
     * Cria uma nova instancia de BlowfishCrypt, com a chave especificada.
     * 
     * @param key
     *            - Chave a ser utilizada
     * @throws InvalidKeyException
     * @throws InvalidKeySpecException
     */
    public BlowfishCrypt(byte[] key) throws InvalidKeyException, InvalidKeySpecException {
	super(ALGORITHM, key);
    }

    /**
     * Cria uma nova instancia de BlowfishCrypt, com a chave especificada.
     * 
     * @param key
     *            - Chave a ser utilizada
     * @throws InvalidKeyException
     * @throws InvalidKeySpecException
     */
    public BlowfishCrypt(String key) throws InvalidKeyException, InvalidKeySpecException, IOException {
	super(ALGORITHM, key);
    }

    /**
     * Cria uma nova instancia de BlowfishCrypt, com a chave gerada no momento da construção.
     * 
     */
    public BlowfishCrypt() {
	super(ALGORITHM);
    }
}
