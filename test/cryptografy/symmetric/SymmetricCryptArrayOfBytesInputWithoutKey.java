package cryptografy.symmetric;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import cryptografy.algorithm.SymmetricAlgorithm;

public class SymmetricCryptArrayOfBytesInputWithoutKey extends SymmetricCryptModelTest {
    @Override
    protected void assertUsingTheAltorithm(SymmetricAlgorithm a) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, SecurityException, IllegalArgumentException, InvalidKeySpecException, IOException, NoSuchMethodException,
    InstantiationException, IllegalAccessException, InvocationTargetException {
	assertEquals(BYTE_ARRAY_DATA, encriptAndDecript(usingTheCryptografy(a), BYTE_ARRAY_DATA));
    }
}
