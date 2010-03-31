package cryptografy;

import cryptografy.asymmetric.AsymmetricCryptFactory;
import cryptografy.symmetric.SymmetricCryptFactory;

/**
 * Obt�m uma f�brica de Criptografia (Sim�trica ou Assim�trica)
 * */
public class CryptFactory {
    /**
     * Obt�m uma f�brica de criptografias sim�tricas.
     * 
     * @return uma f�brica de criptografias sim�tricas.
     */
    public static SymmetricCryptFactory symmetric() {
	return SymmetricCryptFactory.getInstance();
    }

    /**
     * Obt�m uma f�brica de criptografias assim�tricas.
     * 
     * @return uma f�brica de criptografias assim�tricas.
     */
    public static AsymmetricCryptFactory asymmetric() {
	return AsymmetricCryptFactory.getInstance();
    }

}
