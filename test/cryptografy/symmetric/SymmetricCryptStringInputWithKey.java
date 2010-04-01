package cryptografy.symmetric;

import cryptografy.algorithm.SymmetricAlgorithm;
public class SymmetricCryptStringInputWithKey extends SymmetricCryptModelTest {

    @Override
    protected void assertUsingTheAltorithm(final SymmetricAlgorithm a) throws Throwable {
	final SymmetricCryptFactory factory = SymmetricCryptFactory.getInstance();
	final SymmetricCrypter sc = factory.getCryptografy(a);
	sc.generateKey();
	final byte[] sKey = sc.getSerializedKey();

	final SymmetricCrypter toEncrypt = factory.getCryptografy(a, sKey);
	final String encrypted = toEncrypt.encrypt(ALPHA_NUMBER_DATA);

	final SymmetricCrypter toDecrypt = factory.getCryptografy(a, sKey);
	assertEquals(ALPHA_NUMBER_DATA, toDecrypt.decrypt(encrypted));
    }

}
