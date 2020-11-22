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

public final class PublicKey {
	private static final BigInteger TWO = new BigInteger("2");
	
	////////////////////////////////////////////////////////////////////////////////////////////////////
	
	private final BigInteger x;
	private final BigInteger y;
	
	////////////////////////////////////////////////////////////////////////////////////////////////////
	
	public PublicKey(final BigInteger x, final BigInteger y) {
		this.x = Objects.requireNonNull(x, "x == null");
		this.y = Objects.requireNonNull(y, "y == null");
	}
	
	////////////////////////////////////////////////////////////////////////////////////////////////////
	
	public Address toAddress() {
		return toAddress(false);
	}
	
	public Address toAddress(final boolean isCompressed) {
		return new Address(Utilities.computeHashUsingRIPEMD160(Utilities.computeHashUsingSHA256(toByteArray(isCompressed))));
	}
	
	public BigInteger getX() {
		return this.x;
	}
	
	public BigInteger getY() {
		return this.y;
	}
	
	public BigInteger toBigInteger() {
		return toBigInteger(false);
	}
	
	public BigInteger toBigInteger(final boolean isCompressed) {
		if(isCompressed) {
			return new BigInteger(String.format("04%s%s", this.x.toString(16), this.y.toString(16)), 16);
		} else if(doIsEven()) {
			return new BigInteger(String.format("02%s", this.x.toString(16)), 16);
		} else {
			return new BigInteger(String.format("03%s", this.x.toString(16)), 16);
		}
	}
	
	@Override
	public String toString() {
		return toStringHex();
	}
	
	public String toStringDec() {
		return String.format("(%s,%s)", this.x.toString(10), this.y.toString(10));
	}
	
	public String toStringHex() {
		return String.format("(%s,%s)", this.x.toString(16), this.y.toString(16));
	}
	
	@Override
	public boolean equals(final Object object) {
		if(object == this) {
			return true;
		} else if(!(object instanceof PublicKey)) {
			return false;
		} else if(!Objects.equals(this.x, PublicKey.class.cast(object).x)) {
			return false;
		} else if(!Objects.equals(this.y, PublicKey.class.cast(object).y)) {
			return false;
		} else {
			return true;
		}
	}
	
	public byte[] toByteArray() {
		return toByteArray(false);
	}
	
	public byte[] toByteArray(final boolean isCompressed) {
		return toBigInteger(isCompressed).toByteArray();
	}
	
	@Override
	public int hashCode() {
		return Objects.hash(this.x, this.y);
	}
	
	////////////////////////////////////////////////////////////////////////////////////////////////////
	
	private boolean doIsEven() {
		return this.y.mod(TWO).equals(BigInteger.ZERO);
	}
}