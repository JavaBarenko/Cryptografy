package cryptografy.symmetric;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import cryptografy.algorithm.SymmetricAlgorithm;

/**
 * Implementa o uso do algoritmo PBEWithMD5AndDES.
 */
public class PBEWithMD5AndDESCrypt extends SymmetricCrypterImpl {
    private static final int SALT_LENGTH = 32;
    /**
     * Indica o Algoritmo implementado
     */
    public static final SymmetricAlgorithm ALGORITHM = SymmetricAlgorithm.PBEWithMD5AndDES;
    private final PBEParameterSpec parameterSpec = new PBEParameterSpec(new byte[] { 3, 1, 4, 1, 5, 9, 2, 6 }, 20);

    /**
     * Cria uma nova instancia de PBEWithMD5AndDESCrypt, com a chave especificada.
     * 
     * @param key
     *            - Chave a ser utilizada
     * @throws InvalidKeyException
     * @throws InvalidKeySpecException
     */
    public PBEWithMD5AndDESCrypt(final byte[] key) throws IOException, ClassNotFoundException {
	super(ALGORITHM, key);
    }

    /**
     * Cria uma nova instancia de PBEWithMD5AndDESCrypt, com a chave especificada.
     * 
     * @param key
     *            - Chave a ser utilizada
     * @throws InvalidKeyException
     * @throws InvalidKeySpecException
     */
    public PBEWithMD5AndDESCrypt(final String key) throws IOException, ClassNotFoundException {
	super(ALGORITHM, key);
    }

    /**
     * Cria uma nova instancia de PBEWithMD5AndDESCrypt, com a chave gerada no momento da construção.
     * 
     */
    public PBEWithMD5AndDESCrypt() {
	super(ALGORITHM);
    }

    @Override
    protected Key customizedKeyGenerator() throws NoSuchAlgorithmException {
	try {
	    final char[] salt = new char[SALT_LENGTH];
	    for (int i = 0; i < SALT_LENGTH; i++) {
		final int x = (int) ((Math.random() * 94 % 94) + 32);
		salt[i] = (char) x;
	    }
	    return SecretKeyFactory.getInstance(ALGORITHM.getAlgorithm()).generateSecret(new PBEKeySpec(salt));
	} catch (final InvalidKeySpecException e) {
	    e.printStackTrace();
	    return null;
	}
    }

    @Override
    protected void cipherInitConfig(final int cipherMode, final Key key) throws InvalidKeyException {
	try {
	    this.cipher.init(cipherMode, key, this.parameterSpec);
	} catch (final InvalidAlgorithmParameterException e) {
	    super.cipherInitConfig(cipherMode, key);
	}
    }
}
