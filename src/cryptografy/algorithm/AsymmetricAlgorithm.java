package cryptografy.algorithm;

/**
 * Representa todos os algoritmos assim�tricos de criptografia que est�o implementados atualmente.
 * */
public enum AsymmetricAlgorithm {
    RSA_1024bits("RSA", 1024);
    private int numBits;
    private String keyAlgorithm;

    AsymmetricAlgorithm(String keyAlgorithm, int numBits) {
	this.numBits = numBits;
	this.keyAlgorithm = keyAlgorithm;
    }

    /**
     * Obt�m a quantia de bits do algoritmo
     * 
     * @return - A quantia de bits do algoritmo
     */
    public Integer getBits() {
	return this.numBits;
    }

    /**
     * Obt�m o nome do algoritmo
     * 
     * @return - O nome do algoritmo
     */
    public String getAlgorithm() {
	return this.keyAlgorithm;
    }
}