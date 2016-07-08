/*
 
Copyright (c) 2000-2015 The Legion of the Bouncy Castle Inc. (http://www.bouncycastle.org)
Copyright 2016, David R. Smith, All Rights Reserved

This file is part of TweetPepper.

TweetPepper is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

TweetPepper is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with TweetPepper.  If not, see <http://www.gnu.org/licenses/>.

 */
package com.cryptoregistry.ml.chacha20;

/**
 * ChaCha20 from BC with Microlibrary packaging.
 * 
 * @author Dave
 *
 */
public class ChaCha20 {
	
	public ChaCha20() {}

	/**
	 * Process buf with the streaming cipher. Key must be 128 or 256 bits. Nonce must be 64 bits. To decrypt,
	 * just pass in buf filled the encrypted bytes instead of the raw ones. 
	 * 
	 * @param key
	 * @param nonce
	 * @param buf
	 */
	public void process(byte[] key, byte[] nonce, byte[] buf) {
		switch(key.length){
			case 16:
			case 32: break;
			default: throw new RuntimeException("key must be 128 or 256 bits in size");
		}
		if(nonce.length != 8) throw new RuntimeException("nonce must be 64 bits in size");
			
		ChaChaEngine e = new ChaChaEngine(Salsa20Engine.DEFAULT_ROUNDS);
		e.init(true, new ParametersWithIV(new KeyParameter(key), nonce));
		e.processBytes(buf, 0, buf.length, buf, 0);
	}
}

interface CipherParameters {
}

class KeyParameter implements CipherParameters {
	private byte[] key;

	public KeyParameter(byte[] key) {
		this(key, 0, key.length);
	}

	public KeyParameter(byte[] key, int keyOff, int keyLen) {
		this.key = new byte[keyLen];

		System.arraycopy(key, keyOff, this.key, 0, keyLen);
	}

	public byte[] getKey() {
		return key;
	}
}

class ParametersWithIV implements CipherParameters {
	private byte[] iv;
	private CipherParameters parameters;

	public ParametersWithIV(CipherParameters parameters, byte[] iv) {
		this(parameters, iv, 0, iv.length);
	}

	public ParametersWithIV(CipherParameters parameters, byte[] iv, int ivOff,
			int ivLen) {
		this.iv = new byte[ivLen];
		this.parameters = parameters;

		System.arraycopy(iv, ivOff, this.iv, 0, ivLen);
	}

	public byte[] getIV() {
		return iv;
	}

	public CipherParameters getParameters() {
		return parameters;
	}
}

class Salsa20Engine {

	public final static int DEFAULT_ROUNDS = 20;

	/** Constants */
	private final static int STATE_SIZE = 16; // 16, 32 bit ints = 64 bytes

	private final int[] TAU_SIGMA = littleEndianToInt(
			toByteArray("expand 16-byte k" + "expand 32-byte k"), 0, 8);

	// from Pack
	private int[] littleEndianToInt(byte[] bs, int off, int count) {
		int[] ns = new int[count];
		for (int i = 0; i < ns.length; ++i) {
			ns[i] = littleEndianToInt(bs, off);
			off += 4;
		}
		return ns;
	}

	protected void packTauOrSigma(int keyLength, int[] state, int stateOffset) {
		int tsOff = (keyLength - 16) / 4;
		state[stateOffset] = TAU_SIGMA[tsOff];
		state[stateOffset + 1] = TAU_SIGMA[tsOff + 1];
		state[stateOffset + 2] = TAU_SIGMA[tsOff + 2];
		state[stateOffset + 3] = TAU_SIGMA[tsOff + 3];
	}

	protected int rounds;

	/*
	 * variables to hold the state of the engine during encryption and
	 * decryption
	 */
	private int index = 0;
	protected int[] engineState = new int[STATE_SIZE]; // state
	protected int[] x = new int[STATE_SIZE]; // internal buffer
	private byte[] keyStream = new byte[STATE_SIZE * 4]; // expanded state, 64
															// bytes
	private boolean initialised = false;

	/*
	 * internal counter
	 */
	private int cW0, cW1, cW2;

	/**
	 * Creates a 20 round Salsa20 engine.
	 */
	public Salsa20Engine() {
		this(DEFAULT_ROUNDS);
	}

	/**
	 * Creates a Salsa20 engine with a specific number of rounds.
	 * 
	 * @param rounds
	 *            the number of rounds (must be an even number).
	 */
	public Salsa20Engine(int rounds) {
		if (rounds <= 0 || (rounds & 1) != 0) {
			throw new IllegalArgumentException(
					"'rounds' must be a positive, even number");
		}

		this.rounds = rounds;
	}

	/**
	 * initialise a Salsa20 cipher.
	 *
	 * @param forEncryption
	 *            whether or not we are for encryption.
	 * @param params
	 *            the parameters required to set up the cipher.
	 * @exception IllegalArgumentException
	 *                if the params argument is inappropriate.
	 */
	public void init(boolean forEncryption, CipherParameters params) {
		/*
		 * Salsa20 encryption and decryption is completely symmetrical, so the
		 * 'forEncryption' is irrelevant. (Like 90% of stream ciphers)
		 */

		if (!(params instanceof ParametersWithIV)) {
			throw new IllegalArgumentException(getAlgorithmName()
					+ " Init parameters must include an IV");
		}

		ParametersWithIV ivParams = (ParametersWithIV) params;

		byte[] iv = ivParams.getIV();
		if (iv == null || iv.length != getNonceSize()) {
			throw new IllegalArgumentException(getAlgorithmName()
					+ " requires exactly " + getNonceSize() + " bytes of IV");
		}

		CipherParameters keyParam = ivParams.getParameters();
		if (keyParam == null) {
			if (!initialised) {
				throw new IllegalStateException(
						getAlgorithmName()
								+ " KeyParameter can not be null for first initialisation");
			}

			setKey(null, iv);
		} else if (keyParam instanceof KeyParameter) {
			setKey(((KeyParameter) keyParam).getKey(), iv);
		} else {
			throw new IllegalArgumentException(
					getAlgorithmName()
							+ " Init parameters must contain a KeyParameter (or null for re-init)");
		}

		reset();

		initialised = true;
	}

	protected int getNonceSize() {
		return 8;
	}

	public String getAlgorithmName() {
		String name = "Salsa20";
		if (rounds != DEFAULT_ROUNDS) {
			name += "/" + rounds;
		}
		return name;
	}

	public byte returnByte(byte in) {
		if (limitExceeded()) {
			throw new MaxBytesExceededException(
					"2^70 byte limit per IV; Change IV");
		}

		byte out = (byte) (keyStream[index] ^ in);
		index = (index + 1) & 63;

		if (index == 0) {
			advanceCounter();
			generateKeyStream(keyStream);
		}

		return out;
	}

	protected void advanceCounter(long diff) {
		int hi = (int) (diff >>> 32);
		int lo = (int) diff;

		if (hi > 0) {
			engineState[9] += hi;
		}

		int oldState = engineState[8];

		engineState[8] += lo;

		if (oldState != 0 && engineState[8] < oldState) {
			engineState[9]++;
		}
	}

	protected void advanceCounter() {
		if (++engineState[8] == 0) {
			++engineState[9];
		}
	}

	protected void retreatCounter(long diff) {
		int hi = (int) (diff >>> 32);
		int lo = (int) diff;

		if (hi != 0) {
			if ((engineState[9] & 0xffffffffL) >= (hi & 0xffffffffL)) {
				engineState[9] -= hi;
			} else {
				throw new IllegalStateException(
						"attempt to reduce counter past zero.");
			}
		}

		if ((engineState[8] & 0xffffffffL) >= (lo & 0xffffffffL)) {
			engineState[8] -= lo;
		} else {
			if (engineState[9] != 0) {
				--engineState[9];
				engineState[8] -= lo;
			} else {
				throw new IllegalStateException(
						"attempt to reduce counter past zero.");
			}
		}
	}

	protected void retreatCounter() {
		if (engineState[8] == 0 && engineState[9] == 0) {
			throw new IllegalStateException(
					"attempt to reduce counter past zero.");
		}

		if (--engineState[8] == -1) {
			--engineState[9];
		}
	}

	public int processBytes(byte[] in, int inOff, int len, byte[] out,
			int outOff) {
		if (!initialised) {
			throw new IllegalStateException(getAlgorithmName()
					+ " not initialised");
		}

		if ((inOff + len) > in.length) {
			throw new DataLengthException("input buffer too short");
		}

		if ((outOff + len) > out.length) {
			throw new OutputLengthException("output buffer too short");
		}

		if (limitExceeded(len)) {
			throw new MaxBytesExceededException(
					"2^70 byte limit per IV would be exceeded; Change IV");
		}

		for (int i = 0; i < len; i++) {
			out[i + outOff] = (byte) (keyStream[index] ^ in[i + inOff]);
			index = (index + 1) & 63;

			if (index == 0) {
				advanceCounter();
				generateKeyStream(keyStream);
			}
		}

		return len;
	}

	public long skip(long numberOfBytes) {
		if (numberOfBytes >= 0) {
			long remaining = numberOfBytes;

			if (remaining >= 64) {
				long count = remaining / 64;

				advanceCounter(count);

				remaining -= count * 64;
			}

			int oldIndex = index;

			index = (index + (int) remaining) & 63;

			if (index < oldIndex) {
				advanceCounter();
			}
		} else {
			long remaining = -numberOfBytes;

			if (remaining >= 64) {
				long count = remaining / 64;

				retreatCounter(count);

				remaining -= count * 64;
			}

			for (long i = 0; i < remaining; i++) {
				if (index == 0) {
					retreatCounter();
				}

				index = (index - 1) & 63;
			}
		}

		generateKeyStream(keyStream);

		return numberOfBytes;
	}

	public long seekTo(long position) {
		reset();

		return skip(position);
	}

	public long getPosition() {
		return getCounter() * 64 + index;
	}

	public void reset() {
		index = 0;
		resetLimitCounter();
		resetCounter();

		generateKeyStream(keyStream);
	}

	protected long getCounter() {
		return ((long) engineState[9] << 32) | (engineState[8] & 0xffffffffL);
	}

	protected void resetCounter() {
		engineState[8] = engineState[9] = 0;
	}

	protected void setKey(byte[] keyBytes, byte[] ivBytes) {
		if (keyBytes != null) {
			if ((keyBytes.length != 16) && (keyBytes.length != 32)) {
				throw new IllegalArgumentException(getAlgorithmName()
						+ " requires 128 bit or 256 bit key");
			}

			int tsOff = (keyBytes.length - 16) / 4;
			engineState[0] = TAU_SIGMA[tsOff];
			engineState[5] = TAU_SIGMA[tsOff + 1];
			engineState[10] = TAU_SIGMA[tsOff + 2];
			engineState[15] = TAU_SIGMA[tsOff + 3];

			// Key
			littleEndianToInt(keyBytes, 0, engineState, 1, 4);
			littleEndianToInt(keyBytes, keyBytes.length - 16, engineState, 11,
					4);
		}

		// IV
		littleEndianToInt(ivBytes, 0, engineState, 6, 2);
	}

	protected void generateKeyStream(byte[] output) {
		salsaCore(rounds, engineState, x);
		intToLittleEndian(x, output, 0);
	}

	/**
	 * Salsa20 function
	 *
	 * @param input
	 *            input data
	 */
	public void salsaCore(int rounds, int[] input, int[] x) {
		if (input.length != 16) {
			throw new IllegalArgumentException();
		}
		if (x.length != 16) {
			throw new IllegalArgumentException();
		}
		if (rounds % 2 != 0) {
			throw new IllegalArgumentException("Number of rounds must be even");
		}

		int x00 = input[0];
		int x01 = input[1];
		int x02 = input[2];
		int x03 = input[3];
		int x04 = input[4];
		int x05 = input[5];
		int x06 = input[6];
		int x07 = input[7];
		int x08 = input[8];
		int x09 = input[9];
		int x10 = input[10];
		int x11 = input[11];
		int x12 = input[12];
		int x13 = input[13];
		int x14 = input[14];
		int x15 = input[15];

		for (int i = rounds; i > 0; i -= 2) {
			x04 ^= rotl(x00 + x12, 7);
			x08 ^= rotl(x04 + x00, 9);
			x12 ^= rotl(x08 + x04, 13);
			x00 ^= rotl(x12 + x08, 18);
			x09 ^= rotl(x05 + x01, 7);
			x13 ^= rotl(x09 + x05, 9);
			x01 ^= rotl(x13 + x09, 13);
			x05 ^= rotl(x01 + x13, 18);
			x14 ^= rotl(x10 + x06, 7);
			x02 ^= rotl(x14 + x10, 9);
			x06 ^= rotl(x02 + x14, 13);
			x10 ^= rotl(x06 + x02, 18);
			x03 ^= rotl(x15 + x11, 7);
			x07 ^= rotl(x03 + x15, 9);
			x11 ^= rotl(x07 + x03, 13);
			x15 ^= rotl(x11 + x07, 18);

			x01 ^= rotl(x00 + x03, 7);
			x02 ^= rotl(x01 + x00, 9);
			x03 ^= rotl(x02 + x01, 13);
			x00 ^= rotl(x03 + x02, 18);
			x06 ^= rotl(x05 + x04, 7);
			x07 ^= rotl(x06 + x05, 9);
			x04 ^= rotl(x07 + x06, 13);
			x05 ^= rotl(x04 + x07, 18);
			x11 ^= rotl(x10 + x09, 7);
			x08 ^= rotl(x11 + x10, 9);
			x09 ^= rotl(x08 + x11, 13);
			x10 ^= rotl(x09 + x08, 18);
			x12 ^= rotl(x15 + x14, 7);
			x13 ^= rotl(x12 + x15, 9);
			x14 ^= rotl(x13 + x12, 13);
			x15 ^= rotl(x14 + x13, 18);
		}

		x[0] = x00 + input[0];
		x[1] = x01 + input[1];
		x[2] = x02 + input[2];
		x[3] = x03 + input[3];
		x[4] = x04 + input[4];
		x[5] = x05 + input[5];
		x[6] = x06 + input[6];
		x[7] = x07 + input[7];
		x[8] = x08 + input[8];
		x[9] = x09 + input[9];
		x[10] = x10 + input[10];
		x[11] = x11 + input[11];
		x[12] = x12 + input[12];
		x[13] = x13 + input[13];
		x[14] = x14 + input[14];
		x[15] = x15 + input[15];
	}

	/**
	 * Rotate left
	 *
	 * @param x
	 *            value to rotate
	 * @param y
	 *            amount to rotate x
	 *
	 * @return rotated x
	 */
	protected int rotl(int x, int y) {
		return (x << y) | (x >>> -y);
	}

	private void resetLimitCounter() {
		cW0 = 0;
		cW1 = 0;
		cW2 = 0;
	}

	private boolean limitExceeded() {
		if (++cW0 == 0) {
			if (++cW1 == 0) {
				return (++cW2 & 0x20) != 0; // 2^(32 + 32 + 6)
			}
		}

		return false;
	}

	/*
	 * this relies on the fact len will always be positive.
	 */
	private boolean limitExceeded(int len) {
		cW0 += len;
		if (cW0 < len && cW0 >= 0) {
			if (++cW1 == 0) {
				return (++cW2 & 0x20) != 0; // 2^(32 + 32 + 6)
			}
		}

		return false;
	}

	// from Pack

	protected int littleEndianToInt(byte[] bs, int off) {
		int n = bs[off] & 0xff;
		n |= (bs[++off] & 0xff) << 8;
		n |= (bs[++off] & 0xff) << 16;
		n |= bs[++off] << 24;
		return n;
	}

	protected void littleEndianToInt(byte[] bs, int bOff, int[] ns,
			int nOff, int count) {
		for (int i = 0; i < count; ++i) {
			ns[nOff + i] = littleEndianToInt(bs, bOff);
			bOff += 4;
		}
	}

	protected void intToLittleEndian(int n, byte[] bs, int off) {
		bs[off] = (byte) (n);
		bs[++off] = (byte) (n >>> 8);
		bs[++off] = (byte) (n >>> 16);
		bs[++off] = (byte) (n >>> 24);
	}

	protected void intToLittleEndian(int[] ns, byte[] bs, int off) {
		for (int i = 0; i < ns.length; ++i) {
			intToLittleEndian(ns[i], bs, off);
			off += 4;
		}
	}

	// from Strings

	private byte[] toByteArray(String string) {
		byte[] bytes = new byte[string.length()];

		for (int i = 0; i != bytes.length; i++) {
			char ch = string.charAt(i);

			bytes[i] = (byte) ch;
		}

		return bytes;
	}

	// Exceptions

	@SuppressWarnings("serial")
	static class RuntimeCryptoException extends RuntimeException {

		public RuntimeCryptoException() {
		}

		public RuntimeCryptoException(String message) {
			super(message);
		}
	}

	@SuppressWarnings("serial")
	static class DataLengthException extends RuntimeCryptoException {

		public DataLengthException() {
		}

		public DataLengthException(String message) {
			super(message);
		}
	}

	@SuppressWarnings("serial")
	static class MaxBytesExceededException extends RuntimeCryptoException {

		public MaxBytesExceededException() {
		}

		public MaxBytesExceededException(String message) {
			super(message);
		}
	}

	@SuppressWarnings("serial")
	static class OutputLengthException extends DataLengthException {
		public OutputLengthException(String msg) {
			super(msg);
		}
	}
}

class ChaChaEngine extends Salsa20Engine {

	public ChaChaEngine(int rounds) {
		super(rounds);
	}

	public String getAlgorithmName() {
		return "ChaCha" + rounds;
	}

	protected void advanceCounter(long diff) {
		int hi = (int) (diff >>> 32);
		int lo = (int) diff;

		if (hi > 0) {
			engineState[13] += hi;
		}

		int oldState = engineState[12];

		engineState[12] += lo;

		if (oldState != 0 && engineState[12] < oldState) {
			engineState[13]++;
		}
	}

	protected void advanceCounter() {
		if (++engineState[12] == 0) {
			++engineState[13];
		}
	}

	protected void retreatCounter(long diff) {
		int hi = (int) (diff >>> 32);
		int lo = (int) diff;

		if (hi != 0) {
			if ((engineState[13] & 0xffffffffL) >= (hi & 0xffffffffL)) {
				engineState[13] -= hi;
			} else {
				throw new IllegalStateException(
						"attempt to reduce counter past zero.");
			}
		}

		if ((engineState[12] & 0xffffffffL) >= (lo & 0xffffffffL)) {
			engineState[12] -= lo;
		} else {
			if (engineState[13] != 0) {
				--engineState[13];
				engineState[12] -= lo;
			} else {
				throw new IllegalStateException(
						"attempt to reduce counter past zero.");
			}
		}
	}

	protected void retreatCounter() {
		if (engineState[12] == 0 && engineState[13] == 0) {
			throw new IllegalStateException(
					"attempt to reduce counter past zero.");
		}

		if (--engineState[12] == -1) {
			--engineState[13];
		}
	}

	protected long getCounter() {
		return ((long) engineState[13] << 32) | (engineState[12] & 0xffffffffL);
	}

	protected void resetCounter() {
		engineState[12] = engineState[13] = 0;
	}

	protected void setKey(byte[] keyBytes, byte[] ivBytes) {
		if (keyBytes != null) {
			if ((keyBytes.length != 16) && (keyBytes.length != 32)) {
				throw new IllegalArgumentException(getAlgorithmName()
						+ " requires 128 bit or 256 bit key");
			}

			packTauOrSigma(keyBytes.length, engineState, 0);

			// Key
			littleEndianToInt(keyBytes, 0, engineState, 4, 4);
			littleEndianToInt(keyBytes, keyBytes.length - 16, engineState, 8, 4);
		}

		// IV
		littleEndianToInt(ivBytes, 0, engineState, 14, 2);
	}

	protected void generateKeyStream(byte[] output) {
		chachaCore(rounds, engineState, x);
		intToLittleEndian(x, output, 0);
	}

	/**
	 * ChaCha function
	 *
	 * @param input
	 *            input data
	 */
	public void chachaCore(int rounds, int[] input, int[] x) {
		if (input.length != 16) {
			throw new IllegalArgumentException();
		}
		if (x.length != 16) {
			throw new IllegalArgumentException();
		}
		if (rounds % 2 != 0) {
			throw new IllegalArgumentException("Number of rounds must be even");
		}

		int x00 = input[0];
		int x01 = input[1];
		int x02 = input[2];
		int x03 = input[3];
		int x04 = input[4];
		int x05 = input[5];
		int x06 = input[6];
		int x07 = input[7];
		int x08 = input[8];
		int x09 = input[9];
		int x10 = input[10];
		int x11 = input[11];
		int x12 = input[12];
		int x13 = input[13];
		int x14 = input[14];
		int x15 = input[15];

		for (int i = rounds; i > 0; i -= 2) {
			x00 += x04;
			x12 = rotl(x12 ^ x00, 16);
			x08 += x12;
			x04 = rotl(x04 ^ x08, 12);
			x00 += x04;
			x12 = rotl(x12 ^ x00, 8);
			x08 += x12;
			x04 = rotl(x04 ^ x08, 7);
			x01 += x05;
			x13 = rotl(x13 ^ x01, 16);
			x09 += x13;
			x05 = rotl(x05 ^ x09, 12);
			x01 += x05;
			x13 = rotl(x13 ^ x01, 8);
			x09 += x13;
			x05 = rotl(x05 ^ x09, 7);
			x02 += x06;
			x14 = rotl(x14 ^ x02, 16);
			x10 += x14;
			x06 = rotl(x06 ^ x10, 12);
			x02 += x06;
			x14 = rotl(x14 ^ x02, 8);
			x10 += x14;
			x06 = rotl(x06 ^ x10, 7);
			x03 += x07;
			x15 = rotl(x15 ^ x03, 16);
			x11 += x15;
			x07 = rotl(x07 ^ x11, 12);
			x03 += x07;
			x15 = rotl(x15 ^ x03, 8);
			x11 += x15;
			x07 = rotl(x07 ^ x11, 7);
			x00 += x05;
			x15 = rotl(x15 ^ x00, 16);
			x10 += x15;
			x05 = rotl(x05 ^ x10, 12);
			x00 += x05;
			x15 = rotl(x15 ^ x00, 8);
			x10 += x15;
			x05 = rotl(x05 ^ x10, 7);
			x01 += x06;
			x12 = rotl(x12 ^ x01, 16);
			x11 += x12;
			x06 = rotl(x06 ^ x11, 12);
			x01 += x06;
			x12 = rotl(x12 ^ x01, 8);
			x11 += x12;
			x06 = rotl(x06 ^ x11, 7);
			x02 += x07;
			x13 = rotl(x13 ^ x02, 16);
			x08 += x13;
			x07 = rotl(x07 ^ x08, 12);
			x02 += x07;
			x13 = rotl(x13 ^ x02, 8);
			x08 += x13;
			x07 = rotl(x07 ^ x08, 7);
			x03 += x04;
			x14 = rotl(x14 ^ x03, 16);
			x09 += x14;
			x04 = rotl(x04 ^ x09, 12);
			x03 += x04;
			x14 = rotl(x14 ^ x03, 8);
			x09 += x14;
			x04 = rotl(x04 ^ x09, 7);

		}

		x[0] = x00 + input[0];
		x[1] = x01 + input[1];
		x[2] = x02 + input[2];
		x[3] = x03 + input[3];
		x[4] = x04 + input[4];
		x[5] = x05 + input[5];
		x[6] = x06 + input[6];
		x[7] = x07 + input[7];
		x[8] = x08 + input[8];
		x[9] = x09 + input[9];
		x[10] = x10 + input[10];
		x[11] = x11 + input[11];
		x[12] = x12 + input[12];
		x[13] = x13 + input[13];
		x[14] = x14 + input[14];
		x[15] = x15 + input[15];
	}
}
