package cryptografy.asymmetric;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAKeyGenParameterSpec;
import cryptografy.algorithm.AsymmetricAlgorithm;
import cryptografy.algorithm.SymmetricAlgorithm;

/**
 * Implementa o uso do algoritmo RSA de 1024 bits com chave de encriptação simétrica AES/CBC/PKCS5Padding para
 * criptografia de mensagem e criptografia AES de 128 bits para a chave.
 * */
public class RSACrypt extends AsymmetricCrypterImpl {
    /**
     * Indica o Algoritmo implementado
     */
    public static final AsymmetricAlgorithm ALGORITHM = AsymmetricAlgorithm.RSA_1024bits;
    protected String encryptSymmetricMessageKeyAlgorithm = "AES/CBC/PKCS5Padding";
    protected SymmetricAlgorithm encryptKeyAlgorithm = SymmetricAlgorithm.AES;
    protected int encryptKeyAlgorithmKeysize = 128;

    /**
     * Cria uma nova instancia de RSACrypt, com chaves geradas no momento da construção e utilizando o padrão de
     * algoritmo simétrico AES de 128 bits na chave.
     * 
     * @throws InvalidKeyException
     * @throws InvalidKeySpecException
     * @throws IOException
     * @throws ClassNotFoundException
     * */
    public RSACrypt() throws InvalidKeyException, InvalidKeySpecException, IOException, ClassNotFoundException {
	super(ALGORITHM);
    }

    /**
     * Cria uma nova instancia de RSACrypt, as chaves indicadas e utilizando o padrão de algoritmo simétrico AES de 128
     * bits na chave.
     * 
     * @param serializedPublicKey
     *            - Chave publica serializada (objeto do tipo PublicKey serializado)
     * @param serializedPrivateKey
     *            - Chave privada serializada (objeto do tipo PrivateKey serializado)
     * @throws InvalidKeyException
     * @throws InvalidKeySpecException
     * @throws IOException
     * @throws ClassNotFoundException
     * */
    public RSACrypt(final KeyPair keys) throws InvalidKeyException, InvalidKeySpecException, IOException, ClassNotFoundException {
	super(ALGORITHM, keys);
    }

    /**
     * Cria uma nova instancia de RSACrypt, as chaves indicadas e utilizando o padrão de algoritmo simétrico AES de 128
     * bits na chave.
     * 
     * @param serializedPublicKey
     *            - Chave publica serializada (objeto do tipo PublicKey serializado)
     * @param serializedPrivateKey
     *            - Chave privada serializada (objeto do tipo PrivateKey serializado)
     * @throws InvalidKeyException
     * @throws InvalidKeySpecException
     * @throws IOException
     * @throws ClassNotFoundException
     */
    public RSACrypt(final byte[] serializedPublicKey, final byte[] serializedPrivateKey) throws InvalidKeyException, InvalidKeySpecException, IOException, ClassNotFoundException {
	super(ALGORITHM, serializedPublicKey, serializedPrivateKey);
    }

    /**
     * Cria uma nova instancia de RSACrypt, as chaves indicadas e utilizando o padrão de algoritmo simétrico AES de 128
     * bits na chave.
     * 
     * @param serializedPublicKey
     *            - Chave publica serializada (objeto do tipo PublicKey serializado)
     * @param serializedPrivateKey
     *            - Chave privada serializada (objeto do tipo PrivateKey serializado)
     * @throws InvalidKeyException
     * @throws InvalidKeySpecException
     * @throws IOException
     * @throws ClassNotFoundException
     */
    public RSACrypt(final byte[] serializedPublicKey) throws InvalidKeyException, InvalidKeySpecException, IOException, ClassNotFoundException {
	super(ALGORITHM, serializedPublicKey);
    }

    @Override
    protected AlgorithmParameterSpec getAlgorithmParameterSpec() {
	return new RSAKeyGenParameterSpec(this.algorithm.getBits(), RSAKeyGenParameterSpec.F4);
    }

}
