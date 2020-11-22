/**
 * Copyright 2020 J&#246;rgen Lundgren
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

import java.math.BigInteger;
import java.util.Objects;

public final class PrivateKey {
	private static final BigInteger P = new BigInteger("0FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);
	private static final BigInteger A = new BigInteger("0");
	private static final BigInteger B = new BigInteger("7");
	private static final BigInteger X = new BigInteger("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16);
	private static final BigInteger Y = new BigInteger("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16);
	private static final Curve CURVE = new Curve(P, A, B);
	private static final Point POINT = new Point(CURVE, X, Y);
	private static final byte BOTH_NET_0_1 = (byte)(0x01);
	private static final byte MAIN_NET_8_0 = (byte)(0x80);
	private static final byte TEST_NET_E_F = (byte)(0xEF);
	private static final char MAIN_NET_K = 'K';
	private static final char MAIN_NET_L = 'L';
	private static final char MAIN_NET_5 = '5';
	private static final char TEST_NET_C = 'c';
	private static final char TEST_NET_9 = '9';
	
	////////////////////////////////////////////////////////////////////////////////////////////////////
	
	private final BigInteger value;
	
	////////////////////////////////////////////////////////////////////////////////////////////////////
	
	public PrivateKey(final BigInteger value) {
		this.value = Objects.requireNonNull(value, "value == null");
	}
	
	////////////////////////////////////////////////////////////////////////////////////////////////////
	
	public BigInteger getValue() {
		return this.value;
	}
	
	public PublicKey toPublicKey() {
		final Point point = Point.multiply(POINT, this.value);
		
		final BigInteger x = point.getX();
		final BigInteger y = point.getY();
		
		return new PublicKey(x, y);
	}
	
	@Override
	public String toString() {
		return toStringHex();
	}
	
	public String toStringDec() {
		return this.value.toString(10);
	}
	
	public String toStringHex() {
		return this.value.toString(16);
	}
	
	public String toStringWIF() {
		return toStringWIF(false);
	}
	
	public String toStringWIF(final boolean isCompressed) {
		return toStringWIF(isCompressed, false);
	}
	
	public String toStringWIF(final boolean isCompressed, final boolean isTestNet) {
		final int value0 = isTestNet ? TEST_NET_E_F & 0xFF : MAIN_NET_8_0 & 0xFF;
		final int valueN = BOTH_NET_0_1 & 0xFF;
		
		final byte[] a = Utilities.convertHexStringToByteArray(toStringHex());
		final byte[] b = isCompressed ? Utilities.array(valueN) : Utilities.array();
		final byte[] c = Utilities.arrayConcatenate(a, b);
		
		return Utilities.base58EncodeChecked(value0, c);
	}
	
	@Override
	public boolean equals(final Object object) {
		if(object == this) {
			return true;
		} else if(!(object instanceof PrivateKey)) {
			return false;
		} else if(!Objects.equals(this.value, PrivateKey.class.cast(object).value)) {
			return false;
		} else {
			return true;
		}
	}
	
	public byte[] toByteArray() {
		return this.value.toByteArray();
	}
	
	@Override
	public int hashCode() {
		return Objects.hash(this.value);
	}
	
	////////////////////////////////////////////////////////////////////////////////////////////////////
	
	public static PrivateKey parseStringDec(final String stringDec) {
		return new PrivateKey(new BigInteger(Objects.requireNonNull(stringDec, "stringDec == null"), 10));
	}
	
	public static PrivateKey parseStringHex(final String stringHex) {
		return new PrivateKey(new BigInteger(Objects.requireNonNull(stringHex, "stringHex == null"), 16));
	}
	
	public static PrivateKey parseStringWIF(final String stringWIF) {
		final boolean isCompressed = doIsCompressed(stringWIF);
		final boolean isMainNet = doIsMainNet(stringWIF);
		final boolean isTestNet = doIsTestNet(stringWIF);
		
		if(isMainNet && isCompressed) {
			final byte[] a = Utilities.base58DecodeChecked(stringWIF);
			final byte[] b = Utilities.arrayTrimLHS(a);
			final byte[] c = Utilities.arrayTrimRHS(b);
			
			final String stringHex = Utilities.convertByteArrayToHexString(c);
			
			return new PrivateKey(new BigInteger(stringHex, 16));
		}
		
		if(isTestNet && isCompressed) {
			final byte[] a = Utilities.base58DecodeChecked(stringWIF);
			final byte[] b = Utilities.arrayTrimLHS(a);
			final byte[] c = Utilities.arrayTrimRHS(b);
			
			final String stringHex = Utilities.convertByteArrayToHexString(c);
			
			return new PrivateKey(new BigInteger(stringHex, 16));
		}
		
		if(isMainNet) {
			final byte[] a = Utilities.base58DecodeChecked(stringWIF);
			final byte[] b = Utilities.arrayTrimLHS(a);
			
			final String stringHex = Utilities.convertByteArrayToHexString(b);
			
			return new PrivateKey(new BigInteger(stringHex, 16));
		}
		
		if(isTestNet) {
			final byte[] a = Utilities.base58DecodeChecked(stringWIF);
			final byte[] b = Utilities.arrayTrimLHS(a);
			
			final String stringHex = Utilities.convertByteArrayToHexString(b);
			
			return new PrivateKey(new BigInteger(stringHex, 16));
		}
		
		throw new IllegalArgumentException("Invalid format: " + stringWIF);
	}
	
	////////////////////////////////////////////////////////////////////////////////////////////////////
	
	private static boolean doIsCompressed(final String stringWIF) {
		final char character = stringWIF.charAt(0);
		
		final boolean isMainNetK = character == MAIN_NET_K;
		final boolean isMainNetL = character == MAIN_NET_L;
		final boolean isTestNetC = character == TEST_NET_C;
		
		return isMainNetK || isMainNetL || isTestNetC;
	}
	
	private static boolean doIsMainNet(final String stringWIF) {
		final char character = stringWIF.charAt(0);
		
		final boolean isK = character == MAIN_NET_K;
		final boolean isL = character == MAIN_NET_L;
		final boolean is5 = character == MAIN_NET_5;
		
		return isK || isL || is5;
	}
	
	private static boolean doIsTestNet(final String stringWIF) {
		final char character = stringWIF.charAt(0);
		
		final boolean isC = character == TEST_NET_C;
		final boolean is9 = character == TEST_NET_9;
		
		return isC || is9;
	}
}