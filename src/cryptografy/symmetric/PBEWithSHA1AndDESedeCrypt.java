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
 * Implementa o uso do algoritmo PBEWithSHA1AndDESede.
 */
public class PBEWithSHA1AndDESedeCrypt extends SymmetricCrypterImpl {
    /**
     * Indica o Algoritmo implementado
     */
    public static final SymmetricAlgorithm ALGORITHM = SymmetricAlgorithm.PBEWithSHA1AndDESede;
    private final PBEParameterSpec parameterSpec = new PBEParameterSpec(new byte[] { 3, 1, 4, 1, 5, 9, 2, 6 }, 20);

    /**
     * Cria uma nova instancia de PBEWithSHA1AndDESedeCrypt, com a chave especificada.
     * 
     * @param key
     *            - Chave a ser utilizada
     * @throws InvalidKeyException
     * @throws InvalidKeySpecException
     */
    public PBEWithSHA1AndDESedeCrypt(final byte[] key) throws IOException, ClassNotFoundException {
	super(ALGORITHM, key);
    }

    /**
     * Cria uma nova instancia de PBEWithSHA1AndDESedeCrypt, com a chave especificada.
     * 
     * @param key
     *            - Chave a ser utilizada
     * @throws InvalidKeyException
     * @throws InvalidKeySpecException
     */
    public PBEWithSHA1AndDESedeCrypt(final String key) throws IOException, ClassNotFoundException {
	super(ALGORITHM, key);
    }

    /**
     * Cria uma nova instancia de PBEWithSHA1AndDESedeCrypt, com a chave gerada no momento da construção.
     * 
     */
    public PBEWithSHA1AndDESedeCrypt() {
	super(ALGORITHM);
    }

    @Override
    protected Key customizedKeyGenerator() throws NoSuchAlgorithmException {
	final String pwdSalt = "05Bc5hswRWpwp1sew+MSoHcj28rQ0MK8";
	try {
	    return SecretKeyFactory.getInstance(ALGORITHM.getAlgorithm()).generateSecret(new PBEKeySpec(pwdSalt.toCharArray()));
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
