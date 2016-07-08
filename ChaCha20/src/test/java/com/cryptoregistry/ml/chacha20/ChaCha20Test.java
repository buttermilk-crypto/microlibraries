package com.cryptoregistry.ml.chacha20;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

import org.junit.*;

import com.cryptoregistry.ml.chacha20.ChaCha20;

public class ChaCha20Test {

	@Test
	public void test0() throws NoSuchAlgorithmException {
		
		ChaCha20 cc = new ChaCha20();
		SecureRandom rand = SecureRandom.getInstanceStrong();
		byte [] key = new byte[32];
		byte [] nonce = new byte[8];
		byte [] msg = new byte[1048*1000];
		byte [] copy = new byte[1048*1000];
				
		rand.nextBytes(key);
		rand.nextBytes(nonce);
		rand.nextBytes(msg);
		
		System.arraycopy(msg, 0, copy, 0, msg.length);
		
		cc.process(key, nonce, msg);
		cc.process(key, nonce, msg);
		
		Assert.assertTrue(Arrays.equals(copy, msg));
		
	}

}
