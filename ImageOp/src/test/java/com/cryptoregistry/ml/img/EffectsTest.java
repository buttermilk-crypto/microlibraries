package com.cryptoregistry.ml.img;

import java.awt.Graphics2D;
import java.awt.image.BufferedImage;
import java.awt.image.BufferedImageOp;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;

import javax.imageio.ImageIO;

import junit.framework.Assert;
import org.junit.Test;

/**
 * Note - this test requires a GraphicsContext
 * 
 * @author Dave
 *
 */
public class EffectsTest {

	@Test
	public void test0() {
		
		if(java.awt.GraphicsEnvironment.isHeadless()) {
			System.err.println("Sorry, cannot run this particular test in this environment.");
			return;
		}
		
		File result = new File("target/date-oil.png");
		if(result.exists())result.delete();
		
		try (
		 InputStream in = this.getClass().getResourceAsStream("/dave.png");
		){
		
		BufferedImage img = ImageIO.read(in);
		BufferedImageOp op = new Effects().oilFilter();
		Graphics2D g2d = img.createGraphics();
		g2d.drawImage(img, op, 0, 0);
		g2d.dispose();
		
		ImageIO.write(img, "png", result);
		
		}catch(IOException x){
			Assert.fail();
		}
		
		Assert.assertTrue(result.exists());
		
		
	}

}
