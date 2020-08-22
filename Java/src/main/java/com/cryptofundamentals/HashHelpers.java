package com.cryptofundamentals;

import java.security.MessageDigest;
import java.security.SecureRandom;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class HashHelpers {

    static {
        UseBouncyCastle.please();
    }

    public static byte[] computeHash(String message) throws Exception {
        var sha512 = MessageDigest.getInstance("SHA512", "BC");
        sha512.update(message.getBytes());
        return sha512.digest();
    }

	public static byte[] generateSalt() {
        var random = new SecureRandom();
        var bytes = new byte[16];
        random.nextBytes(bytes);
		return bytes;
	}

	public static byte[] deriveKey(String passphrase, byte[] salt) throws Exception {
        var pbkdf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256", "BC");
        int iterationCount = 10000;
        int keyLength = 256;
        var keyMaterial = new PBEKeySpec(passphrase.toCharArray(),
            salt, iterationCount, keyLength);
		SecretKey secretKey = pbkdf.generateSecret(keyMaterial);
        return secretKey.getEncoded();
	}
}