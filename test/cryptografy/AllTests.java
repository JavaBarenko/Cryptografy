package cryptografy;

import junit.framework.Test;
import junit.framework.TestSuite;
import cryptografy.asymmetric.AsymmetricCryptArrayOfBytesInputWithoutKey;
import cryptografy.asymmetric.AsymmetricCryptStringInputWithKey;
import cryptografy.asymmetric.AsymmetricCryptStringInputWithoutKey;
import cryptografy.symmetric.SymmetricCryptArrayOfBytesInputWithoutKey;
import cryptografy.symmetric.SymmetricCryptStringInputWithKey;
import cryptografy.symmetric.SymmetricCryptStringInputWithoutKey;

public class AllTests {
    // Insira aqui todos os pacotes que devem ser testados
    public static final String[] TEST_PACKAGES = { "cryptografy" };

    public static void main(final String[] args) {
	org.junit.runner.JUnitCore.main(AllTests.class.getName());
    }

    public static Test suite() {
	final TestSuite suite = new TestSuite("Test for cryptografy.*");
	// $JUnit-BEGIN$
	staticInvoke(suite);
	// $JUnit-END$
	return suite;
    }

    private static void staticInvoke(final TestSuite suite) {
	suite.addTestSuite(SymmetricCryptArrayOfBytesInputWithoutKey.class);
	suite.addTestSuite(SymmetricCryptStringInputWithKey.class);
	suite.addTestSuite(SymmetricCryptStringInputWithoutKey.class);

	suite.addTestSuite(AsymmetricCryptArrayOfBytesInputWithoutKey.class);
	suite.addTestSuite(AsymmetricCryptStringInputWithKey.class);
	suite.addTestSuite(AsymmetricCryptStringInputWithoutKey.class);
    }
}
