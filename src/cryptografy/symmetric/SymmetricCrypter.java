package cryptografy.symmetric;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import cryptografy.algorithm.SymmetricAlgorithm;

/**
 * Representa um encriptador assimétrico.
 *
 * @author Rafael Caetano Pinto
 *
 */
public interface SymmetricCrypter {
    /**
     * Criptografa o conteudo recebido utilizando o algoritmo especificado na criação da classe.
     *
     * @param input
     *            - Conteúdo a ser criptografado
     * @return O conteúdo criptografado
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    String encrypt(String input) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException;

    /**
     * Criptografa o conteudo recebido utilizando o algoritmo especificado na criação da classe.
     *
     * @param input
     *            - Conteúdo a ser criptografado
     * @return O conteúdo criptografado
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    byte[] encrypt(byte[] input) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException;

    /**
     * Descriptografa o conteudo criptografado recebido utilizando o algoritmo especificado na criação da classe. <br>
     * Em seguida retorna a String com o conteúdo descriptografado.
     *
     * @param input
     *            - Conteúdo a ser descriptografado
     * @return O conteúdo descriptografado
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws IOException
     */
    String decrypt(String input) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException;

    /**
     * Descriptografa o conteudo criptografado recebido utilizando o algoritmo especificado na criação da classe. <br>
     * Em seguida retorna a String com o conteúdo descriptografado.
     *
     * @param input
     *            - Conteúdo a ser descriptografado
     * @return O conteúdo descriptografado
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    byte[] decrypt(byte[] input) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException;

    /**
     * Obtém a chave utilizada na criptografia
     *
     * @return A chave utilizada na criptografia
     */
    Key getKey();

    byte[] getSerializedKey();

    /**
     * Gera uma chave para criptografia.
     *
     * @return - A chave gerada
     * @throws InvalidKeyException
     * @throws InvalidKeySpecException
     */
    void generateKey() throws InvalidKeyException, InvalidKeySpecException;

    void loadKey(byte[] serializedKey) throws IOException, ClassNotFoundException;

    Key deserializeKey(byte[] serializedKey) throws IOException, ClassNotFoundException;

    byte[] serializeKey(Key key);

    SymmetricAlgorithm getAlgorithm();
}
