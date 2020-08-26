package com.cryptofundamentals;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

public class AsymmetricHelpers {

    static {
        UseBouncyCastle.please();
    }

    public static KeyPair generateRsaKey() throws Exception {

        return null;
    }

    public static byte[] encryptWithRsa(PublicKey publicKey, SecretKey key) throws Exception {

        var rsa = Cipher.getInstance("SelectCipher", "BC");
        rsa.init(Cipher.ENCRYPT_MODE, publicKey);

        return null;
    }

    public static byte[] decryptWithRsa(PrivateKey privateKey, byte[] encryptedKey) throws Exception {

        var rsa = Cipher.getInstance("SelectCipher", "BC");
        rsa.init(Cipher.DECRYPT_MODE, privateKey);

        return null;
    }

    public static byte[] signMessage(PrivateKey privateKey, byte[] messageBytes) throws Exception {

        var signature = Signature.getInstance("SelectAlgorithm", "BC");

        return null;
    }

    public static boolean verifySignature(PublicKey publicKey, byte[] messageBytes, byte[] signatureBytes) throws Exception {

        var signature = Signature.getInstance("SelectAlgorithm", "BC");

        return false;
    }
}