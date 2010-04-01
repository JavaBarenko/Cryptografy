package cryptografy.asymmetric;

import cryptografy.algorithm.AsymmetricAlgorithm;

public class AsymmetricCryptStringInputWithKey extends AsymmetricCryptModelTest {

    @Override
    protected void assertUsingTheAltorithm(final AsymmetricAlgorithm a) throws Throwable {
	final AsymmetricCryptFactory factory = AsymmetricCryptFactory.getInstance();
	final AsymmetricCrypter sc = factory.getCryptografy(a);
	sc.generateKeys();
	final byte[] pubK = sc.getSerializedPublicKey();
	final byte[] privK = sc.getSerializedPrivateKey();

	final AsymmetricCrypter toEncrypt = factory.getCryptografy(a, pubK, privK);
	final EncryptSet es = toEncrypt.encrypt(ALPHA_NUMBER_DATA);
	final String encrypted = es.getContents();
	final String encryptedKey = es.getEncryptedKey();

	final AsymmetricCrypter toDecrypt = factory.getCryptografy(a, pubK);
	assertEquals(ALPHA_NUMBER_DATA, toDecrypt.decrypt(encrypted, encryptedKey));
    }

}
