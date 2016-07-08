package com.cryptoregistry.ml.cubehash;

import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import junit.framework.Assert;

import org.junit.Test;

public class CubeHashTest {

	@Test
	public void test0() throws NoSuchAlgorithmException {
		
		String expected = "RMbeOsbHPDkb8JBst0gmAOwGshbHxUoqhoimpCZ2V30=";
		
		byte [] msg = {0x00,0x01,0x02,0x03};
		
		Digest digest = new CubeHash().cubeHash256Digest();
		digest.digest(msg);
		
		byte [] result = digest.digest();
		String val = new String(Base64.getEncoder().encode(result), StandardCharsets.UTF_8);
		Assert.assertTrue(expected.equals(val));
	}

}
