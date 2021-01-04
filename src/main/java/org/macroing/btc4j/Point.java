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

import java.math.BigInteger;
import java.util.Objects;

final class Point {
	private static final BigInteger THREE = new BigInteger("3");
	private static final BigInteger TWO = new BigInteger("2");
	private static final Point INFINITY = new Point(new Curve(BigInteger.ZERO, BigInteger.ZERO, BigInteger.ZERO), BigInteger.ZERO, BigInteger.ZERO);
	
	////////////////////////////////////////////////////////////////////////////////////////////////////
	
	private BigInteger x;
	private BigInteger y;
	private Curve curve;
	
	////////////////////////////////////////////////////////////////////////////////////////////////////
	
	public Point(final Curve curve, final BigInteger x, final BigInteger y) {
		this.curve = Objects.requireNonNull(curve, "curve == null");
		this.x = Objects.requireNonNull(x, "x == null");
		this.y = Objects.requireNonNull(y, "y == null");
	}
	
	////////////////////////////////////////////////////////////////////////////////////////////////////
	
	public BigInteger getX() {
		return this.x;
	}
	
	public BigInteger getY() {
		return this.y;
	}
	
	public Curve getCurve() {
		return this.curve;
	}
	
	@Override
	public String toString() {
		return equals(INFINITY) ? "infinity" : String.format("(%s,%s)", this.x.toString(), this.y.toString());
	}
	
	@Override
	public boolean equals(final Object object) {
		if(object == this) {
			return true;
		} else if(!(object instanceof Point)) {
			return false;
		} else if(!Objects.equals(this.x, Point.class.cast(object).x)) {
			return false;
		} else if(!Objects.equals(this.y, Point.class.cast(object).y)) {
			return false;
		} else if(!Objects.equals(this.curve, Point.class.cast(object).curve)) {
			return false;
		} else {
			return true;
		}
	}
	
	@Override
	public int hashCode() {
		return Objects.hash(this.x, this.y, this.curve);
	}
	
	public void setCurve(final Curve curve) {
		this.curve = Objects.requireNonNull(curve, "curve == null");
	}
	
	public void setX(final BigInteger x) {
		this.x = Objects.requireNonNull(x, "x == null");
	}
	
	public void setY(final BigInteger y) {
		this.y = Objects.requireNonNull(y, "y == null");
	}
	
	////////////////////////////////////////////////////////////////////////////////////////////////////
	
	public static Point add(final Point pointLHS, final Point pointRHS) {
		if(pointRHS.equals(INFINITY)) {
			return pointLHS;
		}
		
		if(pointLHS.equals(INFINITY)) {
			return pointRHS;
		}
		
		if(pointLHS.x.equals(pointRHS.x)) {
			if(pointLHS.y.add(pointRHS.y).mod(pointLHS.curve.getP()).compareTo(BigInteger.ZERO) == 0) {
				return INFINITY;
			}
			
			return multiplyByTwo(pointLHS);
		}
		
		final BigInteger p = pointLHS.curve.getP();
		final BigInteger oldX = pointLHS.x;
		final BigInteger oldY = pointLHS.y;
		final BigInteger l = (pointRHS.y.subtract(oldY).multiply(pointRHS.x.subtract(oldX).modInverse(p))).mod(p);
		final BigInteger newX = l.multiply(l).subtract(oldX).subtract(pointRHS.x).mod(p);
		final BigInteger newY = l.multiply(oldX.subtract(newX)).subtract(oldY).mod(p);
		
		return new Point(pointLHS.curve, newX, newY);
	}
	
	public static Point multiply(final Point pointLHS, final BigInteger valueRHS) {
		final BigInteger e1 = valueRHS;
		
		if(e1.compareTo(BigInteger.ZERO) == 0 || pointLHS.equals(INFINITY)) {
			return INFINITY;
		}
		
		final BigInteger e3 = THREE.multiply(e1);
		
		final Point pointLHSNegatedY = new Point(pointLHS.curve, pointLHS.x, pointLHS.y.negate());
		
		BigInteger i = doLeftMostBit(e3).divide(TWO);
		
		Point result = pointLHS;
		
		while(i.compareTo(BigInteger.ONE) > 0) {
			result = multiplyByTwo(result);
			
			if(e3.and(i).compareTo(BigInteger.ZERO) != 0 && e1.and(i).compareTo(BigInteger.ZERO) == 0) {
				result = add(result, pointLHS);
			}
			
			if(e3.and(i).compareTo(BigInteger.ZERO) == 0 && e1.and(i).compareTo(BigInteger.ZERO) != 0) {
				result = add(result, pointLHSNegatedY);
			}
			
			i = i.divide(TWO);
		}
		
		return result;
	}
	
	public static Point multiplyByTwo(final Point pointLHS) {
		if(pointLHS.equals(INFINITY)) {
			return INFINITY;
		}
		
		final BigInteger p = pointLHS.curve.getP();
		final BigInteger a = pointLHS.curve.getA();
		final BigInteger oldX = pointLHS.x;
		final BigInteger oldY = pointLHS.y;
		final BigInteger l = THREE.multiply(oldX).multiply(oldX).add(a).multiply(TWO.multiply(oldY).modInverse(p)).mod(p);
		final BigInteger newX = l.multiply(l).subtract(TWO.multiply(oldX)).mod(p);
		final BigInteger newY = l.multiply(oldX.subtract(newX)).subtract(oldY).mod(p);
		
		return new Point(pointLHS.curve, newX, newY);
	}
	
	////////////////////////////////////////////////////////////////////////////////////////////////////
	
	private static BigInteger doLeftMostBit(final BigInteger x) {
		BigInteger result = BigInteger.ONE;
		
		while(result.compareTo(x) <= 0) {
			result = TWO.multiply(result);
		}
		
		return result.divide(TWO);
	}
}