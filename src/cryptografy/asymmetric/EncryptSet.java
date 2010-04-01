package cryptografy.asymmetric;

import java.security.Key;
import sun.misc.BASE64Encoder;

public class EncryptSet {
    private static BASE64Encoder encoder = new BASE64Encoder();

    private final byte[] contents;
    private final byte[] encryptedKey;

    private final Key publicKey;

    EncryptSet(final byte[] contents, final byte[] encryptedKey, final Key publicKey) {
	this.contents = contents;
	this.encryptedKey = encryptedKey;
	this.publicKey = publicKey;
    }

    public String getContents() {
	return encoder.encode(this.contents);
    }

    public String getEncryptedKey() {
	return encoder.encode(this.encryptedKey);
    }

    public byte[] getContentsByte() {
	return this.contents;
    }

    public byte[] getEncryptedKeyByte() {
	return this.encryptedKey;
    }

    public Key getPublicKey() {
	return this.publicKey;
    }

    @Override
    public String toString() {
	return String.format("EncryptSet[Contents: %s bytes, PublicKey: %s]", this.contents.length, getEncryptedKey());
    }
}
