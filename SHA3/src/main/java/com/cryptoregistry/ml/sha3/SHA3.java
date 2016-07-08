/*
* Copyright (c) 2000-2015 The Legion of the Bouncy Castle Inc. (http://www.bouncycastle.org)
*/
package com.cryptoregistry.ml.sha3;

import java.util.Arrays;

/**
 * Microlibrary packaging for SHA3 and associated Digests
 * 
 * @author Dave
 *
 */
public class SHA3 {

	public SHA3() {}
	
	public Digest getSHA3Digest() {
		return new SHA3Digest();
	}
	
	public Digest getKeccakDigest() {
		return new KeccakDigest();
	}

	public Digest getSHAKEDigest() {
		return new SHAKEDigest();
	}
}

/**
 * implementation of SHA-3 based on following KeccakNISTInterface.c from
 * http://keccak.noekeon.org/
 * <p>
 * Following the naming conventions used in the C source code to enable easy
 * review of the implementation.
 */
class SHA3Digest extends KeccakDigest {
	private static int checkBitLength(int bitLength) {
		switch (bitLength) {
		case 224:
		case 256:
		case 384:
		case 512:
			return bitLength;
		default:
			throw new IllegalArgumentException("'bitLength' " + bitLength
					+ " not supported for SHA-3");
		}
	}

	SHA3Digest() {
		this(256);
	}

	SHA3Digest(int bitLength) {
		super(checkBitLength(bitLength));
	}

	SHA3Digest(SHA3Digest source) {
		super(source);
	}

	public String getAlgorithmName() {
		return "SHA3-" + fixedOutputLength;
	}

	public int doFinal(byte[] out, int outOff) {
		absorb(new byte[] { 0x02 }, 0, 2);

		return super.doFinal(out, outOff);
	}

	/*
	 * TODO Possible API change to support partial-byte suffixes.
	 */
	protected int doFinal(byte[] out, int outOff, byte partialByte,
			int partialBits) {
		if (partialBits < 0 || partialBits > 7) {
			throw new IllegalArgumentException(
					"'partialBits' must be in the range [0,7]");
		}

		int finalInput = (partialByte & ((1 << partialBits) - 1))
				| (0x02 << partialBits);
		int finalBits = partialBits + 2;

		if (finalBits >= 8) {
			oneByte[0] = (byte) finalInput;
			absorb(oneByte, 0, 8);
			finalBits -= 8;
			finalInput >>>= 8;
		}

		return super.doFinal(out, outOff, (byte) finalInput, finalBits);
	}
}


/**
 * implementation of SHAKE based on following KeccakNISTInterface.c from
 * http://keccak.noekeon.org/
 * <p>
 * Following the naming conventions used in the C source code to enable easy
 * review of the implementation.
 */
class SHAKEDigest extends KeccakDigest implements Xof {
	private static int checkBitLength(int bitLength) {
		switch (bitLength) {
		case 128:
		case 256:
			return bitLength;
		default:
			throw new IllegalArgumentException("'bitLength' " + bitLength
					+ " not supported for SHAKE");
		}
	}

	public SHAKEDigest() {
		this(128);
	}

	public SHAKEDigest(int bitLength) {
		super(checkBitLength(bitLength));
	}

	public SHAKEDigest(SHAKEDigest source) {
		super(source);
	}

	public String getAlgorithmName() {
		return "SHAKE" + fixedOutputLength;
	}

	public int doFinal(byte[] out, int outOff) {
		return doFinal(out, outOff, getDigestSize());
	}

	public int doFinal(byte[] out, int outOff, int outLen) {
		int length = doOutput(out, outOff, outLen);

		reset();

		return length;
	}

	public int doOutput(byte[] out, int outOff, int outLen) {
		if (!squeezing) {
			absorb(new byte[] { 0x0F }, 0, 4);
		}

		squeeze(out, outOff, ((long) outLen) * 8);

		return outLen;
	}

	/*
	 * TODO Possible API change to support partial-byte suffixes.
	 */
	protected int doFinal(byte[] out, int outOff, byte partialByte,
			int partialBits) {
		return doFinal(out, outOff, getDigestSize(), partialByte, partialBits);
	}

	/*
	 * TODO Possible API change to support partial-byte suffixes.
	 */
	protected int doFinal(byte[] out, int outOff, int outLen, byte partialByte,
			int partialBits) {
		if (partialBits < 0 || partialBits > 7) {
			throw new IllegalArgumentException(
					"'partialBits' must be in the range [0,7]");
		}

		int finalInput = (partialByte & ((1 << partialBits) - 1))
				| (0x0F << partialBits);
		int finalBits = partialBits + 4;

		if (finalBits >= 8) {
			oneByte[0] = (byte) finalInput;
			absorb(oneByte, 0, 8);
			finalBits -= 8;
			finalInput >>>= 8;
		}

		if (finalBits > 0) {
			oneByte[0] = (byte) finalInput;
			absorb(oneByte, 0, finalBits);
		}

		squeeze(out, outOff, ((long) outLen) * 8);

		reset();

		return outLen;
	}
}


/**
 * implementation of Keccak based on following KeccakNISTInterface.c from
 * http://keccak.noekeon.org/
 * <p>
 * Following the naming conventions used in the C source code to enable easy
 * review of the implementation.
 */
class KeccakDigest implements ExtendedDigest {
	
	private static long[] KeccakRoundConstants = keccakInitializeRoundConstants();
	private static int[] KeccakRhoOffsets = keccakInitializeRhoOffsets();

	private static long[] keccakInitializeRoundConstants() {
		long[] keccakRoundConstants = new long[24];
		byte[] LFSRstate = new byte[1];

		LFSRstate[0] = 0x01;
		int i, j, bitPosition;

		for (i = 0; i < 24; i++) {
			keccakRoundConstants[i] = 0;
			for (j = 0; j < 7; j++) {
				bitPosition = (1 << j) - 1;
				if (LFSR86540(LFSRstate)) {
					keccakRoundConstants[i] ^= 1L << bitPosition;
				}
			}
		}

		return keccakRoundConstants;
	}

	private static boolean LFSR86540(byte[] LFSR) {
		boolean result = (((LFSR[0]) & 0x01) != 0);
		if (((LFSR[0]) & 0x80) != 0) {
			LFSR[0] = (byte) (((LFSR[0]) << 1) ^ 0x71);
		} else {
			LFSR[0] <<= 1;
		}

		return result;
	}

	private static int[] keccakInitializeRhoOffsets() {
		int[] keccakRhoOffsets = new int[25];
		int x, y, t, newX, newY;

		keccakRhoOffsets[(((0) % 5) + 5 * ((0) % 5))] = 0;
		x = 1;
		y = 0;
		for (t = 0; t < 24; t++) {
			keccakRhoOffsets[(((x) % 5) + 5 * ((y) % 5))] = ((t + 1) * (t + 2) / 2) % 64;
			newX = (0 * x + 1 * y) % 5;
			newY = (2 * x + 3 * y) % 5;
			x = newX;
			y = newY;
		}

		return keccakRhoOffsets;
	}

	protected byte[] state = new byte[(1600 / 8)];
	protected byte[] dataQueue = new byte[(1536 / 8)];
	protected int rate;
	protected int bitsInQueue;
	protected int fixedOutputLength;
	protected boolean squeezing;
	protected int bitsAvailableForSqueezing;
	protected byte[] chunk;
	protected byte[] oneByte;

	private void clearDataQueueSection(int off, int len) {
		for (int i = off; i != off + len; i++) {
			dataQueue[i] = 0;
		}
	}

	KeccakDigest() {
		this(288);
	}

	KeccakDigest(int bitLength) {
		init(bitLength);
	}

	public KeccakDigest(KeccakDigest source) {
		System.arraycopy(source.state, 0, this.state, 0, source.state.length);
		System.arraycopy(source.dataQueue, 0, this.dataQueue, 0,
				source.dataQueue.length);
		this.rate = source.rate;
		this.bitsInQueue = source.bitsInQueue;
		this.fixedOutputLength = source.fixedOutputLength;
		this.squeezing = source.squeezing;
		this.bitsAvailableForSqueezing = source.bitsAvailableForSqueezing;
		this.chunk = cloneBytes(source.chunk);
		this.oneByte = cloneBytes(source.oneByte);
	}

	public String getAlgorithmName() {
		return "Keccak-" + fixedOutputLength;
	}

	public int getDigestSize() {
		return fixedOutputLength / 8;
	}

	public void update(byte in) {
		oneByte[0] = in;

		absorb(oneByte, 0, 8L);
	}

	public void update(byte[] in, int inOff, int len) {
		absorb(in, inOff, len * 8L);
	}

	public int doFinal(byte[] out, int outOff) {
		squeeze(out, outOff, fixedOutputLength);

		reset();

		return getDigestSize();
	}

	/*
	 * TODO Possible API change to support partial-byte suffixes.
	 */
	protected int doFinal(byte[] out, int outOff, byte partialByte,
			int partialBits) {
		if (partialBits > 0) {
			oneByte[0] = partialByte;
			absorb(oneByte, 0, partialBits);
		}

		squeeze(out, outOff, fixedOutputLength);

		reset();

		return getDigestSize();
	}

	public void reset() {
		init(fixedOutputLength);
	}

	/**
	 * Return the size of block that the compression function is applied to in
	 * bytes.
	 *
	 * @return internal byte length of a block.
	 */
	public int getByteLength() {
		return rate / 8;
	}

	private void init(int bitLength) {
		switch (bitLength) {
		case 288:
			initSponge(1024, 576);
			break;
		case 128:
			initSponge(1344, 256);
			break;
		case 224:
			initSponge(1152, 448);
			break;
		case 256:
			initSponge(1088, 512);
			break;
		case 384:
			initSponge(832, 768);
			break;
		case 512:
			initSponge(576, 1024);
			break;
		default:
			throw new IllegalArgumentException(
					"bitLength must be one of 128, 224, 256, 288, 384, or 512.");
		}
	}

	private void initSponge(int rate, int capacity) {
		if (rate + capacity != 1600) {
			throw new IllegalStateException("rate + capacity != 1600");
		}
		if ((rate <= 0) || (rate >= 1600) || ((rate % 64) != 0)) {
			throw new IllegalStateException("invalid rate value");
		}

		this.rate = rate;
		// this is never read, need to check to see why we want to save it
		// this.capacity = capacity;
		Arrays.fill(this.state, (byte) 0);
		Arrays.fill(this.dataQueue, (byte) 0);
		this.bitsInQueue = 0;
		this.squeezing = false;
		this.bitsAvailableForSqueezing = 0;
		this.fixedOutputLength = capacity / 2;
		this.chunk = new byte[rate / 8];
		this.oneByte = new byte[1];
	}

	private void absorbQueue() {
		KeccakAbsorb(state, dataQueue, rate / 8);

		bitsInQueue = 0;
	}

	protected void absorb(byte[] data, int off, long databitlen) {
		long i, j, wholeBlocks;

		if ((bitsInQueue % 8) != 0) {
			throw new IllegalStateException(
					"attempt to absorb with odd length queue");
		}
		if (squeezing) {
			throw new IllegalStateException("attempt to absorb while squeezing");
		}

		i = 0;
		while (i < databitlen) {
			if ((bitsInQueue == 0) && (databitlen >= rate)
					&& (i <= (databitlen - rate))) {
				wholeBlocks = (databitlen - i) / rate;

				for (j = 0; j < wholeBlocks; j++) {
					System.arraycopy(data,
							(int) (off + (i / 8) + (j * chunk.length)), chunk,
							0, chunk.length);

					// displayIntermediateValues.displayBytes(1,
					// "Block to be absorbed", curData, rate / 8);

					KeccakAbsorb(state, chunk, chunk.length);
				}

				i += wholeBlocks * rate;
			} else {
				int partialBlock = (int) (databitlen - i);
				if (partialBlock + bitsInQueue > rate) {
					partialBlock = rate - bitsInQueue;
				}
				int partialByte = partialBlock % 8;
				partialBlock -= partialByte;
				System.arraycopy(data, off + (int) (i / 8), dataQueue,
						bitsInQueue / 8, partialBlock / 8);

				bitsInQueue += partialBlock;
				i += partialBlock;
				if (bitsInQueue == rate) {
					absorbQueue();
				}
				if (partialByte > 0) {
					int mask = (1 << partialByte) - 1;
					dataQueue[bitsInQueue / 8] = (byte) (data[off
							+ ((int) (i / 8))] & mask);
					bitsInQueue += partialByte;
					i += partialByte;
				}
			}
		}
	}

	private void padAndSwitchToSqueezingPhase() {
		if (bitsInQueue + 1 == rate) {
			dataQueue[bitsInQueue / 8] |= 1 << (bitsInQueue % 8);
			absorbQueue();
			clearDataQueueSection(0, rate / 8);
		} else {
			clearDataQueueSection((bitsInQueue + 7) / 8, rate / 8
					- (bitsInQueue + 7) / 8);
			dataQueue[bitsInQueue / 8] |= 1 << (bitsInQueue % 8);
		}
		dataQueue[(rate - 1) / 8] |= 1 << ((rate - 1) % 8);
		absorbQueue();

		// displayIntermediateValues.displayText(1,
		// "--- Switching to squeezing phase ---");

		if (rate == 1024) {
			KeccakExtract1024bits(state, dataQueue);
			bitsAvailableForSqueezing = 1024;
		} else

		{
			KeccakExtract(state, dataQueue, rate / 64);
			bitsAvailableForSqueezing = rate;
		}

		// displayIntermediateValues.displayBytes(1,
		// "Block available for squeezing", dataQueue, bitsAvailableForSqueezing
		// / 8);

		squeezing = true;
	}

	protected void squeeze(byte[] output, int offset, long outputLength) {
		long i;
		int partialBlock;

		if (!squeezing) {
			padAndSwitchToSqueezingPhase();
		}
		if ((outputLength % 8) != 0) {
			throw new IllegalStateException("outputLength not a multiple of 8");
		}

		i = 0;
		while (i < outputLength) {
			if (bitsAvailableForSqueezing == 0) {
				keccakPermutation(state);

				if (rate == 1024) {
					KeccakExtract1024bits(state, dataQueue);
					bitsAvailableForSqueezing = 1024;
				} else

				{
					KeccakExtract(state, dataQueue, rate / 64);
					bitsAvailableForSqueezing = rate;
				}

			}
			partialBlock = bitsAvailableForSqueezing;
			if ((long) partialBlock > outputLength - i) {
				partialBlock = (int) (outputLength - i);
			}

			System.arraycopy(dataQueue, (rate - bitsAvailableForSqueezing) / 8,
					output, offset + (int) (i / 8), partialBlock / 8);
			bitsAvailableForSqueezing -= partialBlock;
			i += partialBlock;
		}
	}

	private void fromBytesToWords(long[] stateAsWords, byte[] state) {
		for (int i = 0; i < (1600 / 64); i++) {
			stateAsWords[i] = 0;
			int index = i * (64 / 8);
			for (int j = 0; j < (64 / 8); j++) {
				stateAsWords[i] |= ((long) state[index + j] & 0xff) << ((8 * j));
			}
		}
	}

	private void fromWordsToBytes(byte[] state, long[] stateAsWords) {
		for (int i = 0; i < (1600 / 64); i++) {
			int index = i * (64 / 8);
			for (int j = 0; j < (64 / 8); j++) {
				state[index + j] = (byte) ((stateAsWords[i] >>> ((8 * j))) & 0xFF);
			}
		}
	}

	private void keccakPermutation(byte[] state) {
		long[] longState = new long[state.length / 8];

		fromBytesToWords(longState, state);

		keccakPermutationOnWords(longState);

		fromWordsToBytes(state, longState);
	}

	private void keccakPermutationAfterXor(byte[] state, byte[] data, int dataLengthInBytes) {
		int i;

		for (i = 0; i < dataLengthInBytes; i++) {
			state[i] ^= data[i];
		}

		keccakPermutation(state);
	}

	private void keccakPermutationOnWords(long[] state) {
		int i;

		// displayIntermediateValues.displayStateAs64bitWords(3,
		// "Same, with lanes as 64-bit words", state);

		for (i = 0; i < 24; i++) {
			// displayIntermediateValues.displayRoundNumber(3, i);

			theta(state);
			// displayIntermediateValues.displayStateAs64bitWords(3,
			// "After theta", state);

			rho(state);
			// displayIntermediateValues.displayStateAs64bitWords(3,
			// "After rho", state);

			pi(state);
			// displayIntermediateValues.displayStateAs64bitWords(3, "After pi",
			// state);

			chi(state);
			// displayIntermediateValues.displayStateAs64bitWords(3,
			// "After chi", state);

			iota(state, i);
			// displayIntermediateValues.displayStateAs64bitWords(3,
			// "After iota", state);
		}
	}

	long[] C = new long[5];

	private void theta(long[] A) {
		for (int x = 0; x < 5; x++) {
			C[x] = 0;
			for (int y = 0; y < 5; y++) {
				C[x] ^= A[x + 5 * y];
			}
		}
		for (int x = 0; x < 5; x++) {
			long dX = ((((C[(x + 1) % 5]) << 1) ^ ((C[(x + 1) % 5]) >>> (64 - 1))))
					^ C[(x + 4) % 5];
			for (int y = 0; y < 5; y++) {
				A[x + 5 * y] ^= dX;
			}
		}
	}

	private void rho(long[] A) {
		for (int x = 0; x < 5; x++) {
			for (int y = 0; y < 5; y++) {
				int index = x + 5 * y;
				A[index] = ((KeccakRhoOffsets[index] != 0) ? (((A[index]) << KeccakRhoOffsets[index]) ^ ((A[index]) >>> (64 - KeccakRhoOffsets[index])))
						: A[index]);
			}
		}
	}

	long[] tempA = new long[25];

	private void pi(long[] A) {
		System.arraycopy(A, 0, tempA, 0, tempA.length);

		for (int x = 0; x < 5; x++) {
			for (int y = 0; y < 5; y++) {
				A[y + 5 * ((2 * x + 3 * y) % 5)] = tempA[x + 5 * y];
			}
		}
	}

	long[] chiC = new long[5];

	private void chi(long[] A) {
		for (int y = 0; y < 5; y++) {
			for (int x = 0; x < 5; x++) {
				chiC[x] = A[x + 5 * y]
						^ ((~A[(((x + 1) % 5) + 5 * y)]) & A[(((x + 2) % 5) + 5 * y)]);
			}
			for (int x = 0; x < 5; x++) {
				A[x + 5 * y] = chiC[x];
			}
		}
	}

	private void iota(long[] A, int indexRound) {
		A[(((0) % 5) + 5 * ((0) % 5))] ^= KeccakRoundConstants[indexRound];
	}

	private void KeccakAbsorb(byte[] byteState, byte[] data, int dataInBytes) {
		keccakPermutationAfterXor(byteState, data, dataInBytes);
	}

	private void KeccakExtract1024bits(byte[] byteState, byte[] data) {
		System.arraycopy(byteState, 0, data, 0, 128);
	}

	private void KeccakExtract(byte[] byteState, byte[] data, int laneCount) {
		System.arraycopy(byteState, 0, data, 0, laneCount * 8);
	}

	// from Arrays
	private byte[] cloneBytes(byte[] data) {
		if (data == null) {
			return null;
		}
		byte[] copy = new byte[data.length];

		System.arraycopy(data, 0, copy, 0, data.length);

		return copy;
	}

}

// Interfaces

interface Digest {

	public String getAlgorithmName();

	public int getDigestSize();

	public void update(byte in);

	public void update(byte[] in, int inOff, int len);

	public int doFinal(byte[] out, int outOff);

	public void reset();
}

interface ExtendedDigest extends Digest {
	public int getByteLength();
}

interface Xof extends ExtendedDigest {

	int doFinal(byte[] out, int outOff, int outLen);

	int doOutput(byte[] out, int outOff, int outLen);
}

