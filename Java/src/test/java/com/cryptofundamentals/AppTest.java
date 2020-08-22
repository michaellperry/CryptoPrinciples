package com.cryptofundamentals;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Unit test for simple App.
 */
public class AppTest 
    extends TestCase
{
    static {
		Security.addProvider(new BouncyCastleProvider());
	}

    public void testGenerateRandomAESKey() throws Exception
    {
		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES", "BC");
		keyGenerator.init(256);
		SecretKey key = keyGenerator.generateKey();

		assertEquals("AES", key.getAlgorithm());
		assertEquals(32, key.getEncoded().length);
    }
}
