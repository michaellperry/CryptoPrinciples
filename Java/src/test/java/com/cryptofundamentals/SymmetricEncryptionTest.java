package com.cryptofundamentals;

import static org.junit.Assert.assertEquals;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.junit.Test;

public class SymmetricEncryptionTest {

  @Test
  public void testGenerateRandomAESKey() throws Exception {
    SecretKey key = Crypto.generateAesKey();

    assertEquals("AES", key.getAlgorithm());
    assertEquals(32, key.getEncoded().length);
  }

  @Test
  public void testEncryptAMessageWithAES() throws Exception {
    String inputMessage = "Alice knows Bob's secret.";

    SecretKey key = Crypto.generateAesKey();
    IvParameterSpec iv = Crypto.generateInitializationVector();

    byte[] cipertext = Crypto.encryptWithAes(inputMessage, key, iv);
    String outputMessage = Crypto.decryptWithAes(cipertext, key, iv);

    assertEquals(inputMessage, outputMessage);
  }
}
