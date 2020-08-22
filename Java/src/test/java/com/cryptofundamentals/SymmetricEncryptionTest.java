package com.cryptofundamentals;

import static org.junit.Assert.assertEquals;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;

public class SymmetricEncryptionTest {

  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  @Test
  public void testGenerateRandomAESKey() throws Exception {
    var keyGenerator = KeyGenerator.getInstance("AES", "BC");
    keyGenerator.init(256);
    var key = keyGenerator.generateKey();

    assertEquals("AES", key.getAlgorithm());
    assertEquals(32, key.getEncoded().length);
  }

  @Test
  public void testEncryptAMessageWithAES() throws Exception {
    var message = "Alice knows Bob's secret.";

    var keyGenerator = KeyGenerator.getInstance("AES", "BC");
    keyGenerator.init(256);
    var key = keyGenerator.generateKey();

    var random = new SecureRandom();
    var buffer = new byte[16];
    random.nextBytes(buffer);
    var iv = new IvParameterSpec(buffer);

    var cipertext = encryptWithAes(message, key, iv);
    var actualMessage = decryptWithAes(cipertext, key, iv);

    assertEquals(message, actualMessage);
  }

  private byte[] encryptWithAes(String message, SecretKey key, IvParameterSpec iv) throws Exception {
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

  private String decryptWithAes(byte[] cipertext, SecretKey key, IvParameterSpec iv) throws Exception {
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
}
