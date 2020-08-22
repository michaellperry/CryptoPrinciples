package com.cryptofundamentals;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.SecretKey;

import org.junit.Test;

public class AsymmetricEncryptionTest {

    @Test
    public void testGenerateRSAKeyPair() throws Exception {
        KeyPair keyPair = Crypto.generateRsaKey();

        assertEquals("RSA", keyPair.getPublic().getAlgorithm());
        assertTrue(keyPair.getPublic().getEncoded().length > 2048 / 8);
        assertTrue(keyPair.getPrivate().getEncoded().length > 2048 / 8);
    }

    @Test
    public void testEncryptSymmetricKey() throws Exception {
        KeyPair keyPair = Crypto.generateRsaKey();

        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        SecretKey key = Crypto.generateAesKey();

        byte[] encryptedKey = Crypto.encryptWithRsa(publicKey, key);
        byte[] decryptedKey = Crypto.decryptWithRsa(privateKey, encryptedKey);

        assertArrayEquals(key.getEncoded(), decryptedKey);
    }

    @Test
    public void testSignMessage() throws Exception {
        KeyPair keyPair = Crypto.generateRsaKey();

        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        String message = "Alice knows Bob's secret.";
        byte[] messageBytes = message.getBytes();

        byte[] signatureBytes = Crypto.signMessage(privateKey, messageBytes);
        boolean verified = Crypto.verifySignature(publicKey, messageBytes, signatureBytes);

        assertTrue(verified);
    }
}