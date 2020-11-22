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

import java.util.Arrays;
import java.util.Objects;

public final class Address {
	private final byte[] bytes;
	
	////////////////////////////////////////////////////////////////////////////////////////////////////
	
	public Address(final byte[] bytes) {
		this.bytes = Objects.requireNonNull(bytes, "bytes == null");
	}
	
	////////////////////////////////////////////////////////////////////////////////////////////////////
	
	@Override
	public String toString() {
		return toStringBase58();
	}
	
	public String toStringBase58() {
		return Utilities.base58EncodeChecked(0x00, this.bytes);
	}
	
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
	
	public byte[] getBytes() {
		return this.bytes;
	}
	
	@Override
	public int hashCode() {
		return Objects.hash(Integer.valueOf(Arrays.hashCode(this.bytes)));
	}
}