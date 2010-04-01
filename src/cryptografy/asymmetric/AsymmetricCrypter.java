package cryptografy.asymmetric;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import cryptografy.algorithm.AsymmetricAlgorithm;

/**
 * Representa um encriptador assimétrico.
 *
 * @author Rafael Caetano Pinto
 *
 */
public interface AsymmetricCrypter {

    /**
     * Criptografa o conteudo recebido utilizando o algoritmo especificado na criação da classe. Em seguida retorna um
     * array de String com 2 itens, onde: <br>
     * <li>item zero: Conteúdo criptografado<br> <li>item um: Chave criptografada referente ao conteúdo<br>
     *
     * @param input
     *            - Conteúdo a ser criptografado
     * @return O conteúdo e a chave criptografados
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws IOException
     */
    EncryptSet encrypt(String input) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException;

    /**
     * Criptografa o conteudo recebido utilizando o algoritmo especificado na criação da classe. Em seguida retorna um
     * array de byte[] com 2 itens, onde: <br>
     * <li>item zero: Conteúdo criptografado<br> <li>item um: Chave criptografada referente ao conteúdo<br>
     *
     * @param input
     *            - Conteúdo a ser criptografado
     * @return O conteúdo e a chave criptografados
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    EncryptSet encrypt(byte[] input) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException;

    /**
     * Descriptografa o conteudo criptografado recebido utilizando o algoritmo especificado na criação da classe e a
     * chave criptografada da mensagem. Em seguida retorna a String com o conteúdo descriptografado.
     * 
     * @param input
     *            - Conteúdo a ser descriptografado
     * @param encryptedKey
     *            - Chave da mensagem para descriptografia
     * @return O conteúdo descriptografado
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws IOException
     */
    String decrypt(String input, String encryptedKey) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException;

    /**
     * chave criptografada da mensagem. Em seguida retorna a String com o conteúdo descriptografado.
     * 
     * @param input
     *            - Conteúdo a ser descriptografado
     * @param encryptedKey
     *            - Chave da mensagem para descriptografia
     * @return O conteúdo descriptografado
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    byte[] decrypt(byte[] input, byte[] encryptedKey) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException;

    /**
     * Obtém o par de chaves publica e privada utilizados na criptografia
     * 
     * @return O par de chaves utilizado
     */
    KeyPair getKeys();

    /**
     * Obtém a chave publica serializada
     *
     * @return - A serialização do objeto PublicKey
     * */
    byte[] getSerializedPublicKey();

    /**
     * Obtém a chave privada serializada
     *
     * @return - A serialização do objeto PrivateKey
     * */
    byte[] getSerializedPrivateKey();

    /**
     * Gera um par de chaves publica e privada.
     *
     * @return - O par de chaves publica e privada gerado
     * @throws InvalidKeyException
     * @throws InvalidKeySpecException
     * @throws IOException
     * @throws ClassNotFoundException
     */
    void generateKeys() throws InvalidKeyException, InvalidKeySpecException, IOException, ClassNotFoundException;

    /**
     * Desserializa as chaves publicas e privadas convertendo-as em um objeto KeyPair.<br>
     * Caso ambas as chaves sejam nulas, esse metodo terá o mesmo efeito de generateKeys() sem argumentos.
     *
     * @param publicKey
     *            - A chave publica serializada
     * @param privateKey
     *            - A chave privada serializada
     *
     * @return - O par de chaves publica e privada gerado ou convertido
     * @throws InvalidKeyException
     * @throws InvalidKeySpecException
     * @throws IOException
     * @throws ClassNotFoundException
     */
    void loadKeys(byte[] serializedPublicKey, byte[] serializedPrivateKey) throws InvalidKeyException, InvalidKeySpecException, IOException, ClassNotFoundException;

    /**
     * Desserializa a chave passada.
     *
     * @param key
     *            - Chave serializada
     * @return o objeto key desserializado
     * @throws IOException
     * @throws ClassNotFoundException
     */
    Key deserializeKey(byte[] serializedKey) throws IOException, ClassNotFoundException;

    /**
     * Serializa a chave passada.
     *
     * @param key
     *            - A chave que se deseja serializar
     * @return A chave serializada
     */
    byte[] serializeKey(Key key);

    AsymmetricAlgorithm getAlgorithm();
}
