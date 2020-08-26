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
        return null;
    }

	public static byte[] generateSalt() {
        var bytes = new byte[16];
		return bytes;
	}

	public static byte[] deriveKey(String passphrase, byte[] salt) throws Exception {
        int iterationCount = 10000;
        int keyLength = 256;
        
        return null;
	}
}