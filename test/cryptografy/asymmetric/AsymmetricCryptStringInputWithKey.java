package cryptografy.asymmetric;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import cryptografy.algorithm.AsymmetricAlgorithm;

public class AsymmetricCryptStringInputWithKey extends AsymmetricCryptModelTest {

    @Override
    protected void assertUsingTheAltorithm(AsymmetricAlgorithm a) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, SecurityException, IllegalArgumentException, InvalidKeySpecException, IOException, NoSuchMethodException,
    InstantiationException, IllegalAccessException, InvocationTargetException, ClassNotFoundException {
	assertEquals(ALPHA_NUMBER_DATA, encriptAndDecript(usingTheCryptografy(a, useANewKeyOf(a)), ALPHA_NUMBER_DATA));
    }

}
