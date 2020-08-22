package com.cryptofundamentals;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class SymmetricHelpers {

    static {
        UseBouncyCastle.please();
    }

    public static SecretKey generateAesKey() throws Exception {
        return null;
    }

    public static IvParameterSpec generateInitializationVector() {
        var random = new SecureRandom();
        var buffer = new byte[16];
        random.nextBytes(buffer);
        return new IvParameterSpec(buffer);
    }

    public static byte[] encryptWithAes(String message, SecretKey key, IvParameterSpec iv) throws Exception {
        var out = new ByteArrayOutputStream();

        return out.toByteArray();
    }

    public static String decryptWithAes(byte[] cipertext, SecretKey key, IvParameterSpec iv) throws Exception {
        var in = new ByteArrayInputStream(cipertext);

        return null;
    }
}