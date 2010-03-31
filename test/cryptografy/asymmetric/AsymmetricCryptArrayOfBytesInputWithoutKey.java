package cryptografy.asymmetric;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import cryptografy.algorithm.AsymmetricAlgorithm;

public class AsymmetricCryptArrayOfBytesInputWithoutKey extends AsymmetricCryptModelTest {
    @Override
    protected void assertUsingTheAltorithm(AsymmetricAlgorithm a) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, SecurityException, IllegalArgumentException, InvalidKeySpecException, IOException, NoSuchMethodException,
    InstantiationException, IllegalAccessException, InvocationTargetException {
	assertEquals(BYTE_ARRAY_DATA, encriptAndDecript(usingTheCryptografy(a), BYTE_ARRAY_DATA));

    }
}
