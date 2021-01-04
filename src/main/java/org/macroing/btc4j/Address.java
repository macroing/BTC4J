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

import java.util.Arrays;
import java.util.Objects;

/**
 * An {@code Address} represents a Bitcoin address.
 * <p>
 * This class is immutable and thread-safe.
 * 
 * @since 1.0.0
 * @author J&#246;rgen Lundgren
 */
public final class Address {
	private final byte[] bytes;
	
	////////////////////////////////////////////////////////////////////////////////////////////////////
	
	/**
	 * Constructs a new {@code Address} instance.
	 * <p>
	 * If {@code bytes} is {@code null}, a {@code NullPointerException} will be thrown.
	 * <p>
	 * Modifications to {@code bytes} will not affect this {@code Address} instance.
	 * 
	 * @param bytes a {@code byte} array representation of this {@code Address} instance
	 * @throws NullPointerException thrown if, and only if, {@code bytes} is {@code null}
	 */
	public Address(final byte[] bytes) {
		this.bytes = Objects.requireNonNull(bytes, "bytes == null").clone();
	}
	
	////////////////////////////////////////////////////////////////////////////////////////////////////
	
	/**
	 * Returns a {@code String} representation of this {@code Address} instance.
	 * 
	 * @return a {@code String} representation of this {@code Address} instance
	 */
	@Override
	public String toString() {
		return toStringBase58();
	}
	
	/**
	 * Returns a {@code String} representation of this {@code Address} instance using Base 58.
	 * 
	 * @return a {@code String} representation of this {@code Address} instance using Base 58
	 */
	public String toStringBase58() {
		return Utilities.base58EncodeChecked(0x00, this.bytes);
	}
	
	/**
	 * Compares {@code object} to this {@code Address} instance for equality.
	 * <p>
	 * Returns {@code true} if, and only if, {@code object} is an instance of {@code Address}, and their respective values are equal, {@code false} otherwise.
	 * 
	 * @param object the {@code Object} to compare to this {@code Address} instance for equality
	 * @return {@code true} if, and only if, {@code object} is an instance of {@code Address}, and their respective values are equal, {@code false} otherwise
	 */
	@Override
	public boolean equals(final Object object) {
		if(object == this) {
			return true;
		} else if(!(object instanceof Address)) {
			return false;
		} else if(!Arrays.equals(this.bytes, Address.class.cast(object).bytes)) {
			return false;
		} else {
			return true;
		}
	}
	
	/**
	 * Returns a {@code byte} array representation of this {@code Address} instance.
	 * <p>
	 * Modifications to the returned {@code byte} array will not affect this {@code Address} instance.
	 * 
	 * @return a {@code byte} array representation of this {@code Address} instance
	 */
	public byte[] getBytes() {
		return this.bytes.clone();
	}
	
	/**
	 * Returns a hash code for this {@code Address} instance.
	 * 
	 * @return a hash code for this {@code Address} instance
	 */
	@Override
	public int hashCode() {
		return Objects.hash(Integer.valueOf(Arrays.hashCode(this.bytes)));
	}
}