package com.cryptofundamentals;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Crypto {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static SecretKey generateAesKey() throws Exception {
        var keyGenerator = KeyGenerator.getInstance("AES", "BC");
        keyGenerator.init(256);
        return keyGenerator.generateKey();
    }

    public static IvParameterSpec generateInitializationVector() {
        var random = new SecureRandom();
        var buffer = new byte[16];
        random.nextBytes(buffer);
        return new IvParameterSpec(buffer);
    }

    public static byte[] encryptWithAes(String message, SecretKey key, IvParameterSpec iv) throws Exception {
        var out = new ByteArrayOutputStream();
        var aes = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
        aes.init(Cipher.ENCRYPT_MODE, key, iv);
        var cipherOut = new CipherOutputStream(out, aes);
        var writer = new OutputStreamWriter(cipherOut);

        try {
            writer.write(message);
        } finally {
            writer.close();
        }

        return out.toByteArray();
    }

    public static String decryptWithAes(byte[] cipertext, SecretKey key, IvParameterSpec iv) throws Exception {
        var in = new ByteArrayInputStream(cipertext);
        var aes = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
        aes.init(Cipher.DECRYPT_MODE, key, iv);
        var cipherIn = new CipherInputStream(in, aes);
        var reader = new InputStreamReader(cipherIn);
        var bufferedReader = new BufferedReader(reader);

        try {
            return bufferedReader.readLine();
        } finally {
            bufferedReader.close();
        }
    }

    public static KeyPair generateRsaKey() throws Exception {

        var generator = KeyPairGenerator.getInstance("RSA", "BC");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    public static byte[] encryptWithRsa(PublicKey publicKey, SecretKey key) throws Exception {

        var rsa = Cipher.getInstance("RSA/NONE/OAEPWithSHA512AndMGF1Padding", "BC");
        rsa.init(Cipher.ENCRYPT_MODE, publicKey);
        return rsa.doFinal(key.getEncoded());
    }

    public static byte[] decryptWithRsa(PrivateKey privateKey, byte[] encryptedKey) throws Exception {

        var rsa = Cipher.getInstance("RSA/NONE/OAEPWithSHA512AndMGF1Padding", "BC");
        rsa.init(Cipher.DECRYPT_MODE, privateKey);
        return rsa.doFinal(encryptedKey);
    }

    public static byte[] signMessage(PrivateKey privateKey, byte[] messageBytes) throws Exception {

        var signature = Signature.getInstance("SHA512withRSA", "BC");
        signature.initSign(privateKey);
        signature.update(messageBytes);
        return signature.sign();
    }

    public static boolean verifySignature(PublicKey publicKey, byte[] messageBytes, byte[] signatureBytes)
            throws Exception {

        var signature = Signature.getInstance("SHA512withRSA", "BC");
        signature.initVerify(publicKey);
        signature.update(messageBytes);
        return signature.verify(signatureBytes);
    }
}