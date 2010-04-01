package cryptografy.asymmetric;

import cryptografy.algorithm.AsymmetricAlgorithm;

public class AsymmetricCryptStringInputWithoutKey extends AsymmetricCryptModelTest {
    @Override
    protected void assertUsingTheAltorithm(final AsymmetricAlgorithm a) throws Throwable {
	final AsymmetricCryptFactory factory = AsymmetricCryptFactory.getInstance();
	final AsymmetricCrypter toEncrypt = factory.getCryptografy(a);
	toEncrypt.generateKeys();

	final EncryptSet es = toEncrypt.encrypt(ALPHA_NUMBER_DATA);
	final String encrypted = es.getContents();
	final String encryptedKey = es.getEncryptedKey();

	final byte[] pubK = toEncrypt.getSerializedPublicKey();

	final AsymmetricCrypter toDecrypt = factory.getCryptografy(a, pubK);
	assertEquals(ALPHA_NUMBER_DATA, toDecrypt.decrypt(encrypted, encryptedKey));
    }
}
