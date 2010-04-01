Cryptografy
===========

_"Data security is easy"_

**Note**: I'm not a security specialist, so be careful before use this package in critical environments.

What is the goal?
-----------------

Cryptografy is a package that aimed at making easier the use of standard encryptions of Java SE 6.

The following encryptions are currently implemented:

Symmetrics:
1.  AES
2.  Blowfish
3.  DES
4.  DESede
5.  PBEWithMD5AndDES
6.  PBEWithSHA1AndDESede
7.  RC2
8.  RC4

Asymmetrics:
1.  RSA 1024 bits

How can I use it?
-----------------

Is very simple encript/decript a String or byte[], for sample:

Using Symmetric Algorithms:
	SymmetricCryptFactory factory = SymmetricCryptFactory.getInstance();
	//Encrypt
	SymmetricCrypter pbeWithMd5AndDes = factory.getCryptografy(SymmetricAlgorithm.PBEWithMD5AndDES);
	pbeWithMd5AndDes.generateKey();
	String encrypted = pbeWithMd5AndDes.encrypt("input");
	byte[] key = pbeWithMd5AndDes.getSerializedKey();

	//Decrypt
	SymmetricCrypter anotherPbeWithMd5AndDes = factory.getCryptografy(SymmetricAlgorithm.PBEWithMD5AndDES, key);
	String decryptedAgain = anotherPbeWithMd5AndDes.decrypt(encrypted);

    
Using Asymetric algorithms:
	AsymmetricCryptFactory factory = AsymmetricCryptFactory.getInstance();
	//Encrypt
	AsymmetricCrypter rsa = factory.getCryptografy(AsymmetricAlgorithm.RSA_1024bits);
	rsa.generateKeys();
	EncryptSet es = rsa.encrypt("input");
	String encrypted = es.getContents();
	String encryptedKey = es.getEncryptedKey();
	byte[] pubK = rsa.getSerializedPublicKey();
	
	//Decrypt
	AsymmetricCrypter rsap = factory.getCryptografy(AsymmetricAlgorithm.RSA_1024bits,pubK);
	String decryptedAgain = rsap.decrypt(encripted, encryptedKey);
