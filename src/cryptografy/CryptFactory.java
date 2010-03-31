package cryptografy;

import cryptografy.asymmetric.AsymmetricCryptFactory;
import cryptografy.symmetric.SymmetricCryptFactory;

/**
 * Obtém uma fábrica de Criptografia (Simétrica ou Assimétrica)
 * */
public class CryptFactory {
    /**
     * Obtém uma fábrica de criptografias simétricas.
     * 
     * @return uma fábrica de criptografias simétricas.
     */
    public static SymmetricCryptFactory symmetric() {
	return SymmetricCryptFactory.getInstance();
    }

    /**
     * Obtém uma fábrica de criptografias assimétricas.
     * 
     * @return uma fábrica de criptografias assimétricas.
     */
    public static AsymmetricCryptFactory asymmetric() {
	return AsymmetricCryptFactory.getInstance();
    }

}
