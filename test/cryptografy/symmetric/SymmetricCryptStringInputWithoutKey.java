package cryptografy.symmetric;


import cryptografy.algorithm.SymmetricAlgorithm;

public class SymmetricCryptStringInputWithoutKey extends SymmetricCryptModelTest {
    @Override
    protected void assertUsingTheAltorithm(final SymmetricAlgorithm a) throws Throwable {
	final SymmetricCryptFactory factory = SymmetricCryptFactory.getInstance();

	final SymmetricCrypter toEncrypt = factory.getCryptografy(a);
	toEncrypt.generateKey();

	final String encrypted = toEncrypt.encrypt(ALPHA_NUMBER_DATA);
	final byte[] sKey = toEncrypt.getSerializedKey();

	final SymmetricCrypter toDecrypt = factory.getCryptografy(a, sKey);
	assertEquals(ALPHA_NUMBER_DATA, toDecrypt.decrypt(encrypted));
    }
}
