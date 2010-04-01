package cryptografy.symmetric;

import cryptografy.algorithm.SymmetricAlgorithm;

public class SymmetricCryptArrayOfBytesInputWithoutKey extends SymmetricCryptModelTest {
    @Override
    protected void assertUsingTheAltorithm(final SymmetricAlgorithm a) throws Throwable {
	final SymmetricCryptFactory factory = SymmetricCryptFactory.getInstance();

	final SymmetricCrypter toEncrypt = factory.getCryptografy(a);
	toEncrypt.generateKey();

	final byte[] encrypted = toEncrypt.encrypt(BYTE_ARRAY_DATA);
	final byte[] sKey = toEncrypt.getSerializedKey();

	final SymmetricCrypter toDecrypt = factory.getCryptografy(a, sKey);
	assertEquals(BYTE_ARRAY_DATA, toDecrypt.decrypt(encrypted));
    }
}
