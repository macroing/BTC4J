/**
 * Copyright 2020 - 2021 J&#246;rgen Lundgren
 * 
 * This file is part of org.macroing.btc4j.
 * 
 * org.macroing.btc4j is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * org.macroing.btc4j is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public License
 * along with org.macroing.btc4j. If not, see <http://www.gnu.org/licenses/>.
 */
package org.macroing.btc4j;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Objects;

final class Utilities {
	private static final MessageDigest MESSAGE_DIGEST_RIPEMD_160 = new RIPEMD160MessageDigest();
	private static final MessageDigest MESSAGE_DIGEST_SHA_256 = doCreateMessageDigest("SHA-256");
	private static final char ENCODED_ZERO = '1';
	private static final char[] ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".toCharArray();
	private static final int[] INDICES = doCreateIndices();
	
	////////////////////////////////////////////////////////////////////////////////////////////////////
	
	private Utilities() {
		
	}
	
	////////////////////////////////////////////////////////////////////////////////////////////////////
	
	public static String base58EncodeChecked(final int version, final byte[] payload) {
		if(version < 0 || version > 255) {
			throw new IllegalArgumentException();
		}
		
		final byte[] a = arrayConcatenate(array(version), payload);
		final byte[] b = computeHashUsingSHA256(computeHashUsingSHA256(a));
		final byte[] c = arrayConcatenate(a, array(b[0], b[1], b[2], b[3]));
		
		return doBase58Encode(c);
	}
	
	public static String convertByteArrayToHexString(final byte[] bytes) {
		final StringBuilder stringBuilder = new StringBuilder();
		
		for(final byte b : bytes) {
			stringBuilder.append(String.format("%02X", Byte.valueOf(b)));
		}
		
		return stringBuilder.toString();
	}
	
	public static byte[] array(final byte... bytes) {
		return bytes;
	}
	
	public static byte[] array(final int value) {
		return new byte[] {(byte)(value)};
	}
	
	public static byte[] arrayConcatenate(final byte[]... byteArrays) {
		int length = 0;
		
		for(final byte[] byteArray : byteArrays) {
			length += byteArray.length;
		}
		
		final byte[] byteArray = new byte[length];
		
		for(int i = 0, j = 0; i < length && j < byteArrays.length; i += byteArrays[j].length, j++) {
			System.arraycopy(byteArrays[j], 0, byteArray, i, byteArrays[j].length);
		}
		
		return byteArray;
	}
	
	public static byte[] arrayTrimLHS(final byte[] bytes) {
		final byte[] bytesRemaining = new byte[bytes.length - 1];
		
		for(int i = 0; i < bytesRemaining.length; i++) {
			bytesRemaining[i] = bytes[i + 1];
		}
		
		return bytesRemaining;
	}
	
	public static byte[] arrayTrimRHS(final byte[] bytes) {
		final byte[] bytesRemaining = new byte[bytes.length - 1];
		
		for(int i = 0; i < bytesRemaining.length; i++) {
			bytesRemaining[i] = bytes[i];
		}
		
		return bytesRemaining;
	}
	
	public static byte[] base58DecodeChecked(final String input) {
		final byte[] decoded = doBase58Decode(input);
		
		if(decoded.length < 4) {
			throw new IllegalArgumentException();
		}
		
		final byte[] data = Arrays.copyOfRange(decoded, 0, decoded.length - 4);
		final byte[] checksum = Arrays.copyOfRange(decoded, decoded.length - 4, decoded.length);
		final byte[] actualChecksum = Arrays.copyOfRange(computeHashUsingSHA256(computeHashUsingSHA256(data)), 0, 4);
		
		if(!Arrays.equals(checksum, actualChecksum)) {
			throw new IllegalArgumentException();
		}
		
		return data;
	}
	
	public static byte[] computeHashUsingRIPEMD160(final byte[] bytes) {
		return MESSAGE_DIGEST_RIPEMD_160 != null ? MESSAGE_DIGEST_RIPEMD_160.digest(Objects.requireNonNull(bytes, "bytes == null")) : new byte[0];
	}
	
	public static byte[] computeHashUsingSHA256(final byte[] bytes) {
		return MESSAGE_DIGEST_SHA_256 != null ? MESSAGE_DIGEST_SHA_256.digest(Objects.requireNonNull(bytes, "bytes == null")) : new byte[0];
	}
	
	public static byte[] convertHexStringToByteArray(final String string) {
		final int length = string.length();
		
		final byte[] bytes = new byte[length / 2];
		
		for(int i = 0; i < length; i += 2) {
			bytes[i / 2] = (byte)((Character.digit(string.charAt(i), 16) << 4) + Character.digit(string.charAt(i + 1), 16));
		}
		
		return bytes;
	}
	
	////////////////////////////////////////////////////////////////////////////////////////////////////
	
	private static MessageDigest doCreateMessageDigest(final String algorithm) {
		try {
			return MessageDigest.getInstance(algorithm);
		} catch(final NoSuchAlgorithmException e) {
			return null;
		}
	}
	
	private static String doBase58Encode(final byte[] input) {
		if(input.length == 0) {
			return "";
		}       
		
		int zeros = 0;
		
		while(zeros < input.length && input[zeros] == 0) {
			zeros++;
		}
		
		final byte[] inputCopy = Arrays.copyOf(input, input.length);
		
		final char[] encoded = new char[inputCopy.length * 2];
		
		int outputStart = encoded.length;
		
		for(int inputStart = zeros; inputStart < inputCopy.length;) {
			encoded[--outputStart] = ALPHABET[doDivideAndModulo(inputCopy, inputStart, 256, 58)];
			
			if(inputCopy[inputStart] == 0) {
				inputStart++;
			}
		}
		
		while(outputStart < encoded.length && encoded[outputStart] == ENCODED_ZERO) {
			outputStart++;
		}
		
		while(--zeros >= 0) {
			encoded[--outputStart] = ENCODED_ZERO;
		}
		
		return new String(encoded, outputStart, encoded.length - outputStart);
	}
	
	private static byte doDivideAndModulo(final byte[] number, final int firstDigit, final int base, final int divisor) {
		int remainder = 0;
		
		for(int i = firstDigit; i < number.length; i++) {
			final int digit = number[i] & 0xFF;
			final int value = remainder * base + digit;
			
			number[i] = (byte)(value / divisor);
			
			remainder = value % divisor;
		}
		
		return (byte)(remainder);
	}
	
	private static byte[] doBase58Decode(final String input) {
		if(input.length() == 0) {
			return new byte[0];
		}
		
		final byte[] input58 = new byte[input.length()];
		
		for(int i = 0; i < input.length(); i++) {
			final char c = input.charAt(i);
			
			final int digit = c < 128 ? INDICES[c] : -1;
			
			if(digit < 0) {
				throw new RuntimeException();
			}
			
			input58[i] = (byte)(digit);
		}
		
		int zeros = 0;
		
		while(zeros < input58.length && input58[zeros] == 0) {
			zeros++;
		}
		
		final byte[] decoded = new byte[input.length()];
		
		int outputStart = decoded.length;
		
		for(int inputStart = zeros; inputStart < input58.length;) {
			decoded[--outputStart] = doDivideAndModulo(input58, inputStart, 58, 256);
			
			if(input58[inputStart] == 0) {
				inputStart++;
			}
		}
		
		while(outputStart < decoded.length && decoded[outputStart] == 0) {
			outputStart++;
		}
		
		return Arrays.copyOfRange(decoded, outputStart - zeros, decoded.length);
	}
	
	private static int[] doCreateIndices() {
		final int[] indices = new int[128];
		
		Arrays.fill(indices, -1);
		
		for(int i = 0; i < ALPHABET.length; i++) {
			indices[ALPHABET[i]] = i;
		}
		
		return indices;
	}
}