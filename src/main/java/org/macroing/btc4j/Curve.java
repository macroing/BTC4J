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

final class Curve {
	private final BigInteger a;
	private final BigInteger b;
	private final BigInteger p;
	
	////////////////////////////////////////////////////////////////////////////////////////////////////
	
	public Curve(final BigInteger p, final BigInteger a, final BigInteger b) {
		this.p = Objects.requireNonNull(p, "p == null");
		this.a = Objects.requireNonNull(a, "a == null");
		this.b = Objects.requireNonNull(b, "b == null");
	}
	
	////////////////////////////////////////////////////////////////////////////////////////////////////
	
	public BigInteger getA() {
		return this.a;
	}
	
	public BigInteger getB() {
		return this.b;
	}
	
	public BigInteger getP() {
		return this.p;
	}
	
	@Override
	public boolean equals(final Object object) {
		if(object == this) {
			return true;
		} else if(!(object instanceof Curve)) {
			return false;
		} else if(!Objects.equals(this.a, Curve.class.cast(object).a)) {
			return false;
		} else if(!Objects.equals(this.b, Curve.class.cast(object).b)) {
			return false;
		} else if(!Objects.equals(this.p, Curve.class.cast(object).p)) {
			return false;
		} else {
			return true;
		}
	}
	
	@Override
	public int hashCode() {
		return Objects.hash(this.a, this.b, this.p);
	}
}