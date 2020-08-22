package com.cryptofundamentals;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;

public class AsymmetricEncryptionTest {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testGenerateRSAKeyPair() throws Exception {
        var keyPair = generateRsaKey();

        assertEquals("RSA", keyPair.getPublic().getAlgorithm());
        assertTrue(keyPair.getPublic().getEncoded().length > 2048 / 8);
        assertTrue(keyPair.getPrivate().getEncoded().length > 2048 / 8);
    }

    @Test
    public void testEncryptSymmetricKey() throws Exception {
        var keyPair = generateRsaKey();

        var publicKey = keyPair.getPublic();
        var privateKey = keyPair.getPrivate();

        var keyGenerator = KeyGenerator.getInstance("AES", "BC");
        keyGenerator.init(256);
        var key = keyGenerator.generateKey();

        var encryptedKey = encryptWithRsa(publicKey, key);
        var decryptedKey = decryptWithRsa(privateKey, encryptedKey);

        assertArrayEquals(key.getEncoded(), decryptedKey);
    }

    @Test
    public void testSignMessage() throws Exception {
        var keyPair = generateRsaKey();

        var publicKey = keyPair.getPublic();
        var privateKey = keyPair.getPrivate();

        var message = "Alice knows Bob's secret.";
        var messageBytes = message.getBytes();

        var signatureBytes = signMessage(privateKey, messageBytes);
        var verified = verifySignature(publicKey, messageBytes, signatureBytes);

        assertTrue(verified);
    }

    private KeyPair generateRsaKey() throws Exception {

        var generator = KeyPairGenerator.getInstance("RSA", "BC");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private byte[] encryptWithRsa(PublicKey publicKey, SecretKey key) throws Exception {

        var rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
        rsa.init(Cipher.ENCRYPT_MODE, publicKey);
        return rsa.doFinal(key.getEncoded());
    }

    private byte[] decryptWithRsa(PrivateKey privateKey, byte[] encryptedKey) throws Exception {

        var rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
        rsa.init(Cipher.DECRYPT_MODE, privateKey);
        return rsa.doFinal(encryptedKey);
    }

    private byte[] signMessage(PrivateKey privateKey, byte[] messageBytes) throws Exception {

        var signature = Signature.getInstance("SHA512withRSA", "BC");
        signature.initSign(privateKey);
        signature.update(messageBytes);
        return signature.sign();
    }

    private boolean verifySignature(PublicKey publicKey, byte[] messageBytes, byte[] signatureBytes) throws Exception {

        var signature = Signature.getInstance("SHA512withRSA", "BC");
        signature.initVerify(publicKey);
        signature.update(messageBytes);
        return signature.verify(signatureBytes);
    }
}