/**
 * 
 */
package cryptografy.algorithm;

/**
 * Representa todos os algoritmos sim�tricos de criptografia que est�o implementados atualmente.
 * */
public enum SymmetricAlgorithm {
    DES("DES"), DESede("DESede"), PBEWithMD5AndDES("PBEWithMD5AndDES"), AES("AES"), Blowfish("Blowfish"), PBEWithSHA1AndDESede(
		"PBEWithSHA1AndDESede"), RC2("RC2"), RC4("RC4");
    private String keyAlgorithm;

    SymmetricAlgorithm(String keyAlgorithm) {
        this.keyAlgorithm = keyAlgorithm;
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