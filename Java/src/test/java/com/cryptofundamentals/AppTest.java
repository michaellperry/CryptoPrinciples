package com.cryptofundamentals;

import java.security.Security;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import junit.framework.TestCase;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class AppTest extends TestCase {

  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  public void testGenerateRandomAESKey() throws Exception {
    KeyGenerator keyGenerator = KeyGenerator.getInstance("AES", "BC");
    keyGenerator.init(256);
    SecretKey key = keyGenerator.generateKey();

    assertEquals("AES", key.getAlgorithm());
    assertEquals(32, key.getEncoded().length);
  }
}
