package cryptografy.asymmetric;

import cryptografy.algorithm.AsymmetricAlgorithm;

public class AsymmetricCryptArrayOfBytesInputWithoutKey extends AsymmetricCryptModelTest {
    @Override
    protected void assertUsingTheAltorithm(final AsymmetricAlgorithm a) throws Throwable {
	final AsymmetricCryptFactory factory = AsymmetricCryptFactory.getInstance();
	final AsymmetricCrypter toEncrypt = factory.getCryptografy(a);
	toEncrypt.generateKeys();

	final EncryptSet es = toEncrypt.encrypt(BYTE_ARRAY_DATA);
	final byte[] encrypted = es.getContentsByte();
	final byte[] encryptedKey = es.getEncryptedKeyByte();

	final byte[] pubK = toEncrypt.getSerializedPublicKey();

	final AsymmetricCrypter toDecrypt = factory.getCryptografy(a, pubK);
	assertEquals(BYTE_ARRAY_DATA, toDecrypt.decrypt(encrypted, encryptedKey));
    }
}
