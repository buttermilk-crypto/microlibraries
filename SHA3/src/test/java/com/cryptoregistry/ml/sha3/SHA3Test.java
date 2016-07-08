package com.cryptoregistry.ml.sha3;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import junit.framework.Assert;

import org.junit.Test;

public class SHA3Test {

	@Test
	public void test() {
		
		String expected = "M7rVQwiZ7W+L6vPnMrKiytHUC3yd4M/Nx+C8B1aAOhA=";
		
		byte [] in = {0x00,0x01,0x02,0x03};
		
		Digest digest = new SHA3().getSHA3Digest();
		digest.update(in, 0, in.length);
		byte [] result = new byte[digest.getDigestSize()];
		digest.doFinal(result, 0);
		
		String val = new String(Base64.getEncoder().encode(result), StandardCharsets.UTF_8);
		System.err.println(val);
		Assert.assertTrue(expected.equals(val));
	}

}
