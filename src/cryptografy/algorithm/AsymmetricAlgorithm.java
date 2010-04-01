package cryptografy.algorithm;

/**
 * Representa todos os algoritmos assimétricos de criptografia que estão implementados atualmente.
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
     * Obtém a quantia de bits do algoritmo
     * 
     * @return - A quantia de bits do algoritmo
     */
    public Integer getBits() {
	return this.numBits;
    }

    /**
     * Obtém o nome do algoritmo
     * 
     * @return - O nome do algoritmo
     */
    public String getAlgorithm() {
	return this.keyAlgorithm;
    }
}