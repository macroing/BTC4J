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

/**
 * A {@code PublicKey} represents a public key for Bitcoin.
 * <p>
 * This class is immutable and thread-safe.
 * 
 * @since 1.0.0
 * @author J&#246;rgen Lundgren
 */
public final class PublicKey {
	private static final BigInteger TWO = new BigInteger("2");
	
	////////////////////////////////////////////////////////////////////////////////////////////////////
	
	private final BigInteger x;
	private final BigInteger y;
	
	////////////////////////////////////////////////////////////////////////////////////////////////////
	
	/**
	 * Constructs a new {@code PublicKey} instance.
	 * <p>
	 * If either {@code x} or {@code y} are {@code null}, a {@code NullPointerException} will be thrown.
	 * 
	 * @param x a {@code BigInteger} instance that represents the X-coordinate
	 * @param y a {@code BigInteger} instance that represents the Y-coordinate
	 * @throws NullPointerException thrown if, and only if, either {@code x} or {@code y} are {@code null}
	 */
	public PublicKey(final BigInteger x, final BigInteger y) {
		this.x = Objects.requireNonNull(x, "x == null");
		this.y = Objects.requireNonNull(y, "y == null");
	}
	
	////////////////////////////////////////////////////////////////////////////////////////////////////
	
	/**
	 * Returns an {@link Address} instance that represents the address associated with the public key represented by this {@code PublicKey} instance.
	 * <p>
	 * Calling this method is equivalent to the following:
	 * <pre>
	 * {@code
	 * publicKey.toAddress(false);
	 * }
	 * </pre>
	 * 
	 * @return an {@code Address} instance that represents the address associated with the public key represented by this {@code PublicKey} instance
	 */
	public Address toAddress() {
		return toAddress(false);
	}
	
	/**
	 * Returns an {@link Address} instance that represents the address associated with the public key represented by this {@code PublicKey} instance.
	 * 
	 * @param isCompressed {@code true} if, and only if, compression should be used, {@code false} otherwise
	 * @return an {@code Address} instance that represents the address associated with the public key represented by this {@code PublicKey} instance
	 */
	public Address toAddress(final boolean isCompressed) {
		return new Address(Utilities.computeHashUsingRIPEMD160(Utilities.computeHashUsingSHA256(toByteArray(isCompressed))));
	}
	
	/**
	 * Returns the {@code BigInteger} instance associated with this {@code PublicKey} instance and represents the X-coordinate.
	 * 
	 * @return the {@code BigInteger} instance associated with this {@code PublicKey} instance and represents the X-coordinate
	 */
	public BigInteger getX() {
		return this.x;
	}
	
	/**
	 * Returns the {@code BigInteger} instance associated with this {@code PublicKey} instance and represents the Y-coordinate.
	 * 
	 * @return the {@code BigInteger} instance associated with this {@code PublicKey} instance and represents the Y-coordinate
	 */
	public BigInteger getY() {
		return this.y;
	}
	
	/**
	 * Returns a {@code BigInteger} representation of this {@code PrivateKey} instance.
	 * <p>
	 * Calling this method is equivalent to the following:
	 * <pre>
	 * {@code
	 * privateKey.toBigInteger(false);
	 * }
	 * </pre>
	 * 
	 * @return a {@code BigInteger} representation of this {@code PrivateKey} instance
	 */
	public BigInteger toBigInteger() {
		return toBigInteger(false);
	}
	
	/**
	 * Returns a {@code BigInteger} representation of this {@code PrivateKey} instance.
	 * 
	 * @param isCompressed {@code true} if, and only if, compression should be used, {@code false} otherwise
	 * @return a {@code BigInteger} representation of this {@code PrivateKey} instance
	 */
	public BigInteger toBigInteger(final boolean isCompressed) {
		if(isCompressed) {
			return new BigInteger(String.format("04%s%s", this.x.toString(16), this.y.toString(16)), 16);
		} else if(doIsEven()) {
			return new BigInteger(String.format("02%s", this.x.toString(16)), 16);
		} else {
			return new BigInteger(String.format("03%s", this.x.toString(16)), 16);
		}
	}
	
	/**
	 * Returns a {@code String} representation of this {@code PublicKey} instance.
	 * 
	 * @return a {@code String} representation of this {@code PublicKey} instance
	 */
	@Override
	public String toString() {
		return toStringHex();
	}
	
	/**
	 * Returns a {@code String} representation of this {@code PublicKey} instance in decimal format.
	 * 
	 * @return a {@code String} representation of this {@code PublicKey} instance in decimal format
	 */
	public String toStringDec() {
		return String.format("(%s,%s)", this.x.toString(10), this.y.toString(10));
	}
	
	/**
	 * Returns a {@code String} representation of this {@code PublicKey} instance in hexadecimal format.
	 * 
	 * @return a {@code String} representation of this {@code PublicKey} instance in hexadecimal format
	 */
	public String toStringHex() {
		return String.format("(%s,%s)", this.x.toString(16), this.y.toString(16));
	}
	
	/**
	 * Compares {@code object} to this {@code PublicKey} instance for equality.
	 * <p>
	 * Returns {@code true} if, and only if, {@code object} is an instance of {@code PublicKey}, and their respective values are equal, {@code false} otherwise.
	 * 
	 * @param object the {@code Object} to compare to this {@code PublicKey} instance for equality
	 * @return {@code true} if, and only if, {@code object} is an instance of {@code PublicKey}, and their respective values are equal, {@code false} otherwise
	 */
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
	
	/**
	 * Returns a {@code byte} array representation of this {@code PublicKey} instance.
	 * <p>
	 * Calling this method is equivalent to the following:
	 * <pre>
	 * {@code
	 * publicKey.toByteArray(false);
	 * }
	 * </pre>
	 * 
	 * @return a {@code byte} array representation of this {@code PublicKey} instance
	 */
	public byte[] toByteArray() {
		return toByteArray(false);
	}
	
	/**
	 * Returns a {@code byte} array representation of this {@code PublicKey} instance.
	 * <p>
	 * Calling this method is equivalent to the following:
	 * <pre>
	 * {@code
	 * publicKey.toBigInteger(isCompressed).toByteArray();
	 * }
	 * </pre>
	 * 
	 * @param isCompressed {@code true} if, and only if, compression should be used, {@code false} otherwise
	 * @return a {@code byte} array representation of this {@code PublicKey} instance
	 */
	public byte[] toByteArray(final boolean isCompressed) {
		return toBigInteger(isCompressed).toByteArray();
	}
	
	/**
	 * Returns a hash code for this {@code PublicKey} instance.
	 * 
	 * @return a hash code for this {@code PublicKey} instance
	 */
	@Override
	public int hashCode() {
		return Objects.hash(this.x, this.y);
	}
	
	////////////////////////////////////////////////////////////////////////////////////////////////////
	
	private boolean doIsEven() {
		return this.y.mod(TWO).equals(BigInteger.ZERO);
	}
}