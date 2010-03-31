Cryptografy
===========

_"Data security is easy"_

**Note**: I'm not a security specialist, so be careful before use this package in critical environments.

What is the goal?
-----------------

Cryptografy is a package that aimed at making easier the use of standard encryptions of Java SE 6.

The following encryptions are currently implemented:

Symmetrics:
1.AES
2.Blowfish
3.DES
4.DESede
5.PBEWithMD5AndDES
6.PBEWithSHA1AndDESede
7.RC2
8.RC4

Asymmetrics:
1.RSA

How can I use it?
-----------------

Is very simple encript/decript a String or byte[], for sample:

Using Symmetric Algorithms:
	SymmetricCrypter pbeWithMd5AndDes = SymmetricCryptFactory.getInstance().getCryptografy(SymmetricAlgorithm.PBEWithMD5AndDES);

    String encripted = pbeWithMd5AndDes.encrypt("input");

    String decriptedAgain = pbeWithMd5AndDes.decrypt(encripted);
    
And using Asymetric algorithms:
	AsymmetricCrypter rsa = AsymmetricCryptFactory.getInstance().getCryptografy(AsymmetricAlgorithm.RSA_1024bits, publicKey, privateKey);
	String encripted = rsa.encrypt("input");

	AsymmetricCrypter rsap = AsymmetricCryptFactory.getInstance().getCryptografy(AsymmetricAlgorithm.RSA_1024bits);
	String decriptedAgain = rsap.decrypt(encripted, publicKey);
