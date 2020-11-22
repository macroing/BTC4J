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

import java.security.MessageDigest;

final class RIPEMD160MessageDigest extends MessageDigest {
	private byte[] byteBuffer;
	private int byteBufferOffset;
	private int intBufferOffset;
	private int h0;
	private int h1;
	private int h2;
	private int h3;
	private int h4;
	private int[] intBuffer;
	private long byteCount;
	
	////////////////////////////////////////////////////////////////////////////////////////////////////
	
	public RIPEMD160MessageDigest() {
		super("RIPEMD-160");
		
		this.byteBuffer = new byte[4];
		this.byteBufferOffset = 0;
		this.intBufferOffset = 0;
		this.h0 = 0x67452301;
		this.h1 = 0xEFCDAB89;
		this.h2 = 0x98BADCFE;
		this.h3 = 0x10325476;
		this.h4 = 0xC3D2E1F0;
		this.intBuffer = new int[16];
		this.byteCount = 0L;
	}
	
	////////////////////////////////////////////////////////////////////////////////////////////////////
	
	@Override
	protected byte[] engineDigest() {
		final byte[] bytes = new byte[20];
		
		doFinish();
		doUnpackWord(this.h0, bytes,  0);
		doUnpackWord(this.h1, bytes,  4);
		doUnpackWord(this.h2, bytes,  8);
		doUnpackWord(this.h3, bytes, 12);
		doUnpackWord(this.h4, bytes, 16);
		
		engineReset();
		
		return bytes;
	}
	
	@Override
	protected void engineReset() {
		this.byteBuffer = new byte[4];
		this.byteBufferOffset = 0;
		this.intBufferOffset = 0;
		this.h0 = 0x67452301;
		this.h1 = 0xEFCDAB89;
		this.h2 = 0x98BADCFE;
		this.h3 = 0x10325476;
		this.h4 = 0xC3D2E1F0;
		this.intBuffer = new int[16];
		this.byteCount = 0L;
	}
	
	@Override
	protected void engineUpdate(final byte input) {
		this.byteBuffer[this.byteBufferOffset++] = input;
		
		if(this.byteBufferOffset == this.byteBuffer.length) {
			doProcessWord(this.byteBuffer, 0);
			
			this.byteBufferOffset = 0;
		}
		
		this.byteCount++;
	}
	
	@Override
	protected void engineUpdate(final byte[] input, final int offset, final int len) {
		final int length = Math.max(0,  len);
		
		int i = 0;
		
		if(this.byteBufferOffset != 0) {
			while(i < length) {
				this.byteBuffer[this.byteBufferOffset++] = input[offset + i++];
				
				if(this.byteBufferOffset == 4) {
					doProcessWord(this.byteBuffer, 0);
					
					this.byteBufferOffset = 0;
					
					break;
				}
			}
		}
		
		final int limit = ((length - i) & ~3) + i;
		
		for(; i < limit; i += 4) {
			doProcessWord(input, offset + i);
		}
		
		while(i < length) {
			this.byteBuffer[this.byteBufferOffset++] = input[offset + i++];
		}
		
		this.byteCount += length;
	}
	
	////////////////////////////////////////////////////////////////////////////////////////////////////
	
	private void doFinish() {
		final long bitLength = (this.byteCount << 3);
		
		update((byte)(128));
		
		while(this.byteBufferOffset != 0) {
			update((byte)(0));
		}
		
		doProcessLength(bitLength);
		doProcessBlock();
	}
	
	private void doProcessBlock() {
		int a  = this.h0;
		int aa = this.h0;
		int b  = this.h1;
		int bb = this.h1;
		int c  = this.h2;
		int cc = this.h2;
		int d  = this.h3;
		int dd = this.h3;
		int e  = this.h4;
		int ee = this.h4;
		
		a = doRotateLeft(a + doF1(b,c,d) + this.intBuffer[ 0], 11) + e;
		c = doRotateLeft(c, 10);
		e = doRotateLeft(e + doF1(a,b,c) + this.intBuffer[ 1], 14) + d;
		b = doRotateLeft(b, 10);
		d = doRotateLeft(d + doF1(e,a,b) + this.intBuffer[ 2], 15) + c;
		a = doRotateLeft(a, 10);
		c = doRotateLeft(c + doF1(d,e,a) + this.intBuffer[ 3], 12) + b;
		e = doRotateLeft(e, 10);
		b = doRotateLeft(b + doF1(c,d,e) + this.intBuffer[ 4],  5) + a;
		d = doRotateLeft(d, 10);
		a = doRotateLeft(a + doF1(b,c,d) + this.intBuffer[ 5],  8) + e;
		c = doRotateLeft(c, 10);
		e = doRotateLeft(e + doF1(a,b,c) + this.intBuffer[ 6],  7) + d;
		b = doRotateLeft(b, 10);
		d = doRotateLeft(d + doF1(e,a,b) + this.intBuffer[ 7],  9) + c;
		a = doRotateLeft(a, 10);
		c = doRotateLeft(c + doF1(d,e,a) + this.intBuffer[ 8], 11) + b;
		e = doRotateLeft(e, 10);
		b = doRotateLeft(b + doF1(c,d,e) + this.intBuffer[ 9], 13) + a;
		d = doRotateLeft(d, 10);
		a = doRotateLeft(a + doF1(b,c,d) + this.intBuffer[10], 14) + e;
		c = doRotateLeft(c, 10);
		e = doRotateLeft(e + doF1(a,b,c) + this.intBuffer[11], 15) + d;
		b = doRotateLeft(b, 10);
		d = doRotateLeft(d + doF1(e,a,b) + this.intBuffer[12],  6) + c;
		a = doRotateLeft(a, 10);
		c = doRotateLeft(c + doF1(d,e,a) + this.intBuffer[13],  7) + b;
		e = doRotateLeft(e, 10);
		b = doRotateLeft(b + doF1(c,d,e) + this.intBuffer[14],  9) + a;
		d = doRotateLeft(d, 10);
		a = doRotateLeft(a + doF1(b,c,d) + this.intBuffer[15],  8) + e;
		c = doRotateLeft(c, 10);
		
		aa = doRotateLeft(aa + doF5(bb,cc,dd) + this.intBuffer[ 5] + 0x50A28BE6,  8) + ee;
		cc = doRotateLeft(cc, 10);
		ee = doRotateLeft(ee + doF5(aa,bb,cc) + this.intBuffer[14] + 0x50A28BE6,  9) + dd;
		bb = doRotateLeft(bb, 10);
		dd = doRotateLeft(dd + doF5(ee,aa,bb) + this.intBuffer[ 7] + 0x50A28BE6,  9) + cc;
		aa = doRotateLeft(aa, 10);
		cc = doRotateLeft(cc + doF5(dd,ee,aa) + this.intBuffer[ 0] + 0x50A28BE6, 11) + bb;
		ee = doRotateLeft(ee, 10);
		bb = doRotateLeft(bb + doF5(cc,dd,ee) + this.intBuffer[ 9] + 0x50A28BE6, 13) + aa;
		dd = doRotateLeft(dd, 10);
		aa = doRotateLeft(aa + doF5(bb,cc,dd) + this.intBuffer[ 2] + 0x50A28BE6, 15) + ee;
		cc = doRotateLeft(cc, 10);
		ee = doRotateLeft(ee + doF5(aa,bb,cc) + this.intBuffer[11] + 0x50A28BE6, 15) + dd;
		bb = doRotateLeft(bb, 10);
		dd = doRotateLeft(dd + doF5(ee,aa,bb) + this.intBuffer[ 4] + 0x50A28BE6,  5) + cc;
		aa = doRotateLeft(aa, 10);
		cc = doRotateLeft(cc + doF5(dd,ee,aa) + this.intBuffer[13] + 0x50A28BE6,  7) + bb;
		ee = doRotateLeft(ee, 10);
		bb = doRotateLeft(bb + doF5(cc,dd,ee) + this.intBuffer[ 6] + 0x50A28BE6,  7) + aa;
		dd = doRotateLeft(dd, 10);
		aa = doRotateLeft(aa + doF5(bb,cc,dd) + this.intBuffer[15] + 0x50A28BE6,  8) + ee;
		cc = doRotateLeft(cc, 10);
		ee = doRotateLeft(ee + doF5(aa,bb,cc) + this.intBuffer[ 8] + 0x50A28BE6, 11) + dd;
		bb = doRotateLeft(bb, 10);
		dd = doRotateLeft(dd + doF5(ee,aa,bb) + this.intBuffer[ 1] + 0x50A28BE6, 14) + cc;
		aa = doRotateLeft(aa, 10);
		cc = doRotateLeft(cc + doF5(dd,ee,aa) + this.intBuffer[10] + 0x50A28BE6, 14) + bb;
		ee = doRotateLeft(ee, 10);
		bb = doRotateLeft(bb + doF5(cc,dd,ee) + this.intBuffer[ 3] + 0x50A28BE6, 12) + aa;
		dd = doRotateLeft(dd, 10);
		aa = doRotateLeft(aa + doF5(bb,cc,dd) + this.intBuffer[12] + 0x50A28BE6,  6) + ee;
		cc = doRotateLeft(cc, 10);
		
		e = doRotateLeft(e + doF2(a,b,c) + this.intBuffer[ 7] + 0x5A827999,  7) + d;
		b = doRotateLeft(b, 10);
		d = doRotateLeft(d + doF2(e,a,b) + this.intBuffer[ 4] + 0x5A827999,  6) + c;
		a = doRotateLeft(a, 10);
		c = doRotateLeft(c + doF2(d,e,a) + this.intBuffer[13] + 0x5A827999,  8) + b;
		e = doRotateLeft(e, 10);
		b = doRotateLeft(b + doF2(c,d,e) + this.intBuffer[ 1] + 0x5A827999, 13) + a;
		d = doRotateLeft(d, 10);
		a = doRotateLeft(a + doF2(b,c,d) + this.intBuffer[10] + 0x5A827999, 11) + e;
		c = doRotateLeft(c, 10);
		e = doRotateLeft(e + doF2(a,b,c) + this.intBuffer[ 6] + 0x5A827999,  9) + d;
		b = doRotateLeft(b, 10);
		d = doRotateLeft(d + doF2(e,a,b) + this.intBuffer[15] + 0x5A827999,  7) + c;
		a = doRotateLeft(a, 10);
		c = doRotateLeft(c + doF2(d,e,a) + this.intBuffer[ 3] + 0x5A827999, 15) + b;
		e = doRotateLeft(e, 10);
		b = doRotateLeft(b + doF2(c,d,e) + this.intBuffer[12] + 0x5A827999,  7) + a;
		d = doRotateLeft(d, 10);
		a = doRotateLeft(a + doF2(b,c,d) + this.intBuffer[ 0] + 0x5A827999, 12) + e;
		c = doRotateLeft(c, 10);
		e = doRotateLeft(e + doF2(a,b,c) + this.intBuffer[ 9] + 0x5A827999, 15) + d;
		b = doRotateLeft(b, 10);
		d = doRotateLeft(d + doF2(e,a,b) + this.intBuffer[ 5] + 0x5A827999,  9) + c;
		a = doRotateLeft(a, 10);
		c = doRotateLeft(c + doF2(d,e,a) + this.intBuffer[ 2] + 0x5A827999, 11) + b;
		e = doRotateLeft(e, 10);
		b = doRotateLeft(b + doF2(c,d,e) + this.intBuffer[14] + 0x5A827999,  7) + a;
		d = doRotateLeft(d, 10);
		a = doRotateLeft(a + doF2(b,c,d) + this.intBuffer[11] + 0x5A827999, 13) + e;
		c = doRotateLeft(c, 10);
		e = doRotateLeft(e + doF2(a,b,c) + this.intBuffer[ 8] + 0x5A827999, 12) + d;
		b = doRotateLeft(b, 10);
		
		ee = doRotateLeft(ee + doF4(aa,bb,cc) + this.intBuffer[ 6] + 0x5C4DD124,  9) + dd;
		bb = doRotateLeft(bb, 10);
		dd = doRotateLeft(dd + doF4(ee,aa,bb) + this.intBuffer[11] + 0x5C4DD124, 13) + cc;
		aa = doRotateLeft(aa, 10);
		cc = doRotateLeft(cc + doF4(dd,ee,aa) + this.intBuffer[ 3] + 0x5C4DD124, 15) + bb;
		ee = doRotateLeft(ee, 10);
		bb = doRotateLeft(bb + doF4(cc,dd,ee) + this.intBuffer[ 7] + 0x5C4DD124,  7) + aa;
		dd = doRotateLeft(dd, 10);
		aa = doRotateLeft(aa + doF4(bb,cc,dd) + this.intBuffer[ 0] + 0x5C4DD124, 12) + ee;
		cc = doRotateLeft(cc, 10);
		ee = doRotateLeft(ee + doF4(aa,bb,cc) + this.intBuffer[13] + 0x5C4DD124,  8) + dd;
		bb = doRotateLeft(bb, 10);
		dd = doRotateLeft(dd + doF4(ee,aa,bb) + this.intBuffer[ 5] + 0x5C4DD124,  9) + cc;
		aa = doRotateLeft(aa, 10);
		cc = doRotateLeft(cc + doF4(dd,ee,aa) + this.intBuffer[10] + 0x5C4DD124, 11) + bb;
		ee = doRotateLeft(ee, 10);
		bb = doRotateLeft(bb + doF4(cc,dd,ee) + this.intBuffer[14] + 0x5C4DD124,  7) + aa;
		dd = doRotateLeft(dd, 10);
		aa = doRotateLeft(aa + doF4(bb,cc,dd) + this.intBuffer[15] + 0x5C4DD124,  7) + ee;
		cc = doRotateLeft(cc, 10);
		ee = doRotateLeft(ee + doF4(aa,bb,cc) + this.intBuffer[ 8] + 0x5C4DD124, 12) + dd;
		bb = doRotateLeft(bb, 10);
		dd = doRotateLeft(dd + doF4(ee,aa,bb) + this.intBuffer[12] + 0x5C4DD124,  7) + cc;
		aa = doRotateLeft(aa, 10);
		cc = doRotateLeft(cc + doF4(dd,ee,aa) + this.intBuffer[ 4] + 0x5C4DD124,  6) + bb;
		ee = doRotateLeft(ee, 10);
		bb = doRotateLeft(bb + doF4(cc,dd,ee) + this.intBuffer[ 9] + 0x5C4DD124, 15) + aa;
		dd = doRotateLeft(dd, 10);
		aa = doRotateLeft(aa + doF4(bb,cc,dd) + this.intBuffer[ 1] + 0x5C4DD124, 13) + ee;
		cc = doRotateLeft(cc, 10);
		ee = doRotateLeft(ee + doF4(aa,bb,cc) + this.intBuffer[ 2] + 0x5C4DD124, 11) + dd;
		bb = doRotateLeft(bb, 10);
		
		d = doRotateLeft(d + doF3(e,a,b) + this.intBuffer[ 3] + 0x6ED9EBA1, 11) + c;
		a = doRotateLeft(a, 10);
		c = doRotateLeft(c + doF3(d,e,a) + this.intBuffer[10] + 0x6ED9EBA1, 13) + b;
		e = doRotateLeft(e, 10);
		b = doRotateLeft(b + doF3(c,d,e) + this.intBuffer[14] + 0x6ED9EBA1,  6) + a;
		d = doRotateLeft(d, 10);
		a = doRotateLeft(a + doF3(b,c,d) + this.intBuffer[ 4] + 0x6ED9EBA1,  7) + e;
		c = doRotateLeft(c, 10);
		e = doRotateLeft(e + doF3(a,b,c) + this.intBuffer[ 9] + 0x6ED9EBA1, 14) + d;
		b = doRotateLeft(b, 10);
		d = doRotateLeft(d + doF3(e,a,b) + this.intBuffer[15] + 0x6ED9EBA1,  9) + c;
		a = doRotateLeft(a, 10);
		c = doRotateLeft(c + doF3(d,e,a) + this.intBuffer[ 8] + 0x6ED9EBA1, 13) + b;
		e = doRotateLeft(e, 10);
		b = doRotateLeft(b + doF3(c,d,e) + this.intBuffer[ 1] + 0x6ED9EBA1, 15) + a;
		d = doRotateLeft(d, 10);
		a = doRotateLeft(a + doF3(b,c,d) + this.intBuffer[ 2] + 0x6ED9EBA1, 14) + e;
		c = doRotateLeft(c, 10);
		e = doRotateLeft(e + doF3(a,b,c) + this.intBuffer[ 7] + 0x6ED9EBA1,  8) + d;
		b = doRotateLeft(b, 10);
		d = doRotateLeft(d + doF3(e,a,b) + this.intBuffer[ 0] + 0x6ED9EBA1, 13) + c;
		a = doRotateLeft(a, 10);
		c = doRotateLeft(c + doF3(d,e,a) + this.intBuffer[ 6] + 0x6ED9EBA1,  6) + b;
		e = doRotateLeft(e, 10);
		b = doRotateLeft(b + doF3(c,d,e) + this.intBuffer[13] + 0x6ED9EBA1,  5) + a;
		d = doRotateLeft(d, 10);
		a = doRotateLeft(a + doF3(b,c,d) + this.intBuffer[11] + 0x6ED9EBA1, 12) + e;
		c = doRotateLeft(c, 10);
		e = doRotateLeft(e + doF3(a,b,c) + this.intBuffer[ 5] + 0x6ED9EBA1,  7) + d;
		b = doRotateLeft(b, 10);
		d = doRotateLeft(d + doF3(e,a,b) + this.intBuffer[12] + 0x6ED9EBA1,  5) + c;
		a = doRotateLeft(a, 10);
		
		dd = doRotateLeft(dd + doF3(ee,aa,bb) + this.intBuffer[15] + 0x6D703EF3,  9) + cc;
		aa = doRotateLeft(aa, 10);
		cc = doRotateLeft(cc + doF3(dd,ee,aa) + this.intBuffer[ 5] + 0x6D703EF3,  7) + bb;
		ee = doRotateLeft(ee, 10);
		bb = doRotateLeft(bb + doF3(cc,dd,ee) + this.intBuffer[ 1] + 0x6D703EF3, 15) + aa;
		dd = doRotateLeft(dd, 10);
		aa = doRotateLeft(aa + doF3(bb,cc,dd) + this.intBuffer[ 3] + 0x6D703EF3, 11) + ee;
		cc = doRotateLeft(cc, 10);
		ee = doRotateLeft(ee + doF3(aa,bb,cc) + this.intBuffer[ 7] + 0x6D703EF3,  8) + dd;
		bb = doRotateLeft(bb, 10);
		dd = doRotateLeft(dd + doF3(ee,aa,bb) + this.intBuffer[14] + 0x6D703EF3,  6) + cc;
		aa = doRotateLeft(aa, 10);
		cc = doRotateLeft(cc + doF3(dd,ee,aa) + this.intBuffer[ 6] + 0x6D703EF3,  6) + bb;
		ee = doRotateLeft(ee, 10);
		bb = doRotateLeft(bb + doF3(cc,dd,ee) + this.intBuffer[ 9] + 0x6D703EF3, 14) + aa;
		dd = doRotateLeft(dd, 10);
		aa = doRotateLeft(aa + doF3(bb,cc,dd) + this.intBuffer[11] + 0x6D703EF3, 12) + ee;
		cc = doRotateLeft(cc, 10);
		ee = doRotateLeft(ee + doF3(aa,bb,cc) + this.intBuffer[ 8] + 0x6D703EF3, 13) + dd;
		bb = doRotateLeft(bb, 10);
		dd = doRotateLeft(dd + doF3(ee,aa,bb) + this.intBuffer[12] + 0x6D703EF3,  5) + cc;
		aa = doRotateLeft(aa, 10);
		cc = doRotateLeft(cc + doF3(dd,ee,aa) + this.intBuffer[ 2] + 0x6D703EF3, 14) + bb;
		ee = doRotateLeft(ee, 10);
		bb = doRotateLeft(bb + doF3(cc,dd,ee) + this.intBuffer[10] + 0x6D703EF3, 13) + aa;
		dd = doRotateLeft(dd, 10);
		aa = doRotateLeft(aa + doF3(bb,cc,dd) + this.intBuffer[ 0] + 0x6D703EF3, 13) + ee;
		cc = doRotateLeft(cc, 10);
		ee = doRotateLeft(ee + doF3(aa,bb,cc) + this.intBuffer[ 4] + 0x6D703EF3,  7) + dd;
		bb = doRotateLeft(bb, 10);
		dd = doRotateLeft(dd + doF3(ee,aa,bb) + this.intBuffer[13] + 0x6D703EF3,  5) + cc;
		aa = doRotateLeft(aa, 10);
		
		c = doRotateLeft(c + doF4(d,e,a) + this.intBuffer[ 1] + 0x8F1BBCDC, 11) + b;
		e = doRotateLeft(e, 10);
		b = doRotateLeft(b + doF4(c,d,e) + this.intBuffer[ 9] + 0x8F1BBCDC, 12) + a;
		d = doRotateLeft(d, 10);
		a = doRotateLeft(a + doF4(b,c,d) + this.intBuffer[11] + 0x8F1BBCDC, 14) + e;
		c = doRotateLeft(c, 10);
		e = doRotateLeft(e + doF4(a,b,c) + this.intBuffer[10] + 0x8F1BBCDC, 15) + d;
		b = doRotateLeft(b, 10);
		d = doRotateLeft(d + doF4(e,a,b) + this.intBuffer[ 0] + 0x8F1BBCDC, 14) + c;
		a = doRotateLeft(a, 10);
		c = doRotateLeft(c + doF4(d,e,a) + this.intBuffer[ 8] + 0x8F1BBCDC, 15) + b;
		e = doRotateLeft(e, 10);
		b = doRotateLeft(b + doF4(c,d,e) + this.intBuffer[12] + 0x8F1BBCDC,  9) + a;
		d = doRotateLeft(d, 10);
		a = doRotateLeft(a + doF4(b,c,d) + this.intBuffer[ 4] + 0x8F1BBCDC,  8) + e;
		c = doRotateLeft(c, 10);
		e = doRotateLeft(e + doF4(a,b,c) + this.intBuffer[13] + 0x8F1BBCDC,  9) + d;
		b = doRotateLeft(b, 10);
		d = doRotateLeft(d + doF4(e,a,b) + this.intBuffer[ 3] + 0x8F1BBCDC, 14) + c;
		a = doRotateLeft(a, 10);
		c = doRotateLeft(c + doF4(d,e,a) + this.intBuffer[ 7] + 0x8F1BBCDC,  5) + b;
		e = doRotateLeft(e, 10);
		b = doRotateLeft(b + doF4(c,d,e) + this.intBuffer[15] + 0x8F1BBCDC,  6) + a;
		d = doRotateLeft(d, 10);
		a = doRotateLeft(a + doF4(b,c,d) + this.intBuffer[14] + 0x8F1BBCDC,  8) + e;
		c = doRotateLeft(c, 10);
		e = doRotateLeft(e + doF4(a,b,c) + this.intBuffer[ 5] + 0x8F1BBCDC,  6) + d;
		b = doRotateLeft(b, 10);
		d = doRotateLeft(d + doF4(e,a,b) + this.intBuffer[ 6] + 0x8F1BBCDC,  5) + c;
		a = doRotateLeft(a, 10);
		c = doRotateLeft(c + doF4(d,e,a) + this.intBuffer[ 2] + 0x8F1BBCDC, 12) + b;
		e = doRotateLeft(e, 10);
		
		cc = doRotateLeft(cc + doF2(dd,ee,aa) + this.intBuffer[ 8] + 0x7A6D76E9, 15) + bb;
		ee = doRotateLeft(ee, 10);
		bb = doRotateLeft(bb + doF2(cc,dd,ee) + this.intBuffer[ 6] + 0x7A6D76E9,  5) + aa;
		dd = doRotateLeft(dd, 10);
		aa = doRotateLeft(aa + doF2(bb,cc,dd) + this.intBuffer[ 4] + 0x7A6D76E9,  8) + ee;
		cc = doRotateLeft(cc, 10);
		ee = doRotateLeft(ee + doF2(aa,bb,cc) + this.intBuffer[ 1] + 0x7A6D76E9, 11) + dd;
		bb = doRotateLeft(bb, 10);
		dd = doRotateLeft(dd + doF2(ee,aa,bb) + this.intBuffer[ 3] + 0x7A6D76E9, 14) + cc;
		aa = doRotateLeft(aa, 10);
		cc = doRotateLeft(cc + doF2(dd,ee,aa) + this.intBuffer[11] + 0x7A6D76E9, 14) + bb;
		ee = doRotateLeft(ee, 10);
		bb = doRotateLeft(bb + doF2(cc,dd,ee) + this.intBuffer[15] + 0x7A6D76E9,  6) + aa;
		dd = doRotateLeft(dd, 10);
		aa = doRotateLeft(aa + doF2(bb,cc,dd) + this.intBuffer[ 0] + 0x7A6D76E9, 14) + ee;
		cc = doRotateLeft(cc, 10);
		ee = doRotateLeft(ee + doF2(aa,bb,cc) + this.intBuffer[ 5] + 0x7A6D76E9,  6) + dd;
		bb = doRotateLeft(bb, 10);
		dd = doRotateLeft(dd + doF2(ee,aa,bb) + this.intBuffer[12] + 0x7A6D76E9,  9) + cc;
		aa = doRotateLeft(aa, 10);
		cc = doRotateLeft(cc + doF2(dd,ee,aa) + this.intBuffer[ 2] + 0x7A6D76E9, 12) + bb;
		ee = doRotateLeft(ee, 10);
		bb = doRotateLeft(bb + doF2(cc,dd,ee) + this.intBuffer[13] + 0x7A6D76E9,  9) + aa;
		dd = doRotateLeft(dd, 10);
		aa = doRotateLeft(aa + doF2(bb,cc,dd) + this.intBuffer[ 9] + 0x7A6D76E9, 12) + ee;
		cc = doRotateLeft(cc, 10);
		ee = doRotateLeft(ee + doF2(aa,bb,cc) + this.intBuffer[ 7] + 0x7A6D76E9,  5) + dd;
		bb = doRotateLeft(bb, 10);
		dd = doRotateLeft(dd + doF2(ee,aa,bb) + this.intBuffer[10] + 0x7A6D76E9, 15) + cc;
		aa = doRotateLeft(aa, 10);
		cc = doRotateLeft(cc + doF2(dd,ee,aa) + this.intBuffer[14] + 0x7A6D76E9,  8) + bb;
		ee = doRotateLeft(ee, 10);
		
		b = doRotateLeft(b + doF5(c,d,e) + this.intBuffer[ 4] + 0xA953FD4E,  9) + a;
		d = doRotateLeft(d, 10);
		a = doRotateLeft(a + doF5(b,c,d) + this.intBuffer[ 0] + 0xA953FD4E, 15) + e;
		c = doRotateLeft(c, 10);
		e = doRotateLeft(e + doF5(a,b,c) + this.intBuffer[ 5] + 0xA953FD4E,  5) + d;
		b = doRotateLeft(b, 10);
		d = doRotateLeft(d + doF5(e,a,b) + this.intBuffer[ 9] + 0xA953FD4E, 11) + c;
		a = doRotateLeft(a, 10);
		c = doRotateLeft(c + doF5(d,e,a) + this.intBuffer[ 7] + 0xA953FD4E,  6) + b;
		e = doRotateLeft(e, 10);
		b = doRotateLeft(b + doF5(c,d,e) + this.intBuffer[12] + 0xA953FD4E,  8) + a;
		d = doRotateLeft(d, 10);
		a = doRotateLeft(a + doF5(b,c,d) + this.intBuffer[ 2] + 0xA953FD4E, 13) + e;
		c = doRotateLeft(c, 10);
		e = doRotateLeft(e + doF5(a,b,c) + this.intBuffer[10] + 0xA953FD4E, 12) + d;
		b = doRotateLeft(b, 10);
		d = doRotateLeft(d + doF5(e,a,b) + this.intBuffer[14] + 0xA953FD4E,  5) + c;
		a = doRotateLeft(a, 10);
		c = doRotateLeft(c + doF5(d,e,a) + this.intBuffer[ 1] + 0xA953FD4E, 12) + b;
		e = doRotateLeft(e, 10);
		b = doRotateLeft(b + doF5(c,d,e) + this.intBuffer[ 3] + 0xA953FD4E, 13) + a;
		d = doRotateLeft(d, 10);
		a = doRotateLeft(a + doF5(b,c,d) + this.intBuffer[ 8] + 0xA953FD4E, 14) + e;
		c = doRotateLeft(c, 10);
		e = doRotateLeft(e + doF5(a,b,c) + this.intBuffer[11] + 0xA953FD4E, 11) + d;
		b = doRotateLeft(b, 10);
		d = doRotateLeft(d + doF5(e,a,b) + this.intBuffer[ 6] + 0xA953FD4E,  8) + c;
		a = doRotateLeft(a, 10);
		c = doRotateLeft(c + doF5(d,e,a) + this.intBuffer[15] + 0xA953FD4E,  5) + b;
		e = doRotateLeft(e, 10);
		b = doRotateLeft(b + doF5(c,d,e) + this.intBuffer[13] + 0xA953FD4E,  6) + a;
		d = doRotateLeft(d, 10);
		
		bb = doRotateLeft(bb + doF1(cc,dd,ee) + this.intBuffer[12],  8) + aa;
		dd = doRotateLeft(dd, 10);
		aa = doRotateLeft(aa + doF1(bb,cc,dd) + this.intBuffer[15],  5) + ee;
		cc = doRotateLeft(cc, 10);
		ee = doRotateLeft(ee + doF1(aa,bb,cc) + this.intBuffer[10], 12) + dd;
		bb = doRotateLeft(bb, 10);
		dd = doRotateLeft(dd + doF1(ee,aa,bb) + this.intBuffer[ 4],  9) + cc;
		aa = doRotateLeft(aa, 10);
		cc = doRotateLeft(cc + doF1(dd,ee,aa) + this.intBuffer[ 1], 12) + bb;
		ee = doRotateLeft(ee, 10);
		bb = doRotateLeft(bb + doF1(cc,dd,ee) + this.intBuffer[ 5],  5) + aa;
		dd = doRotateLeft(dd, 10);
		aa = doRotateLeft(aa + doF1(bb,cc,dd) + this.intBuffer[ 8], 14) + ee;
		cc = doRotateLeft(cc, 10);
		ee = doRotateLeft(ee + doF1(aa,bb,cc) + this.intBuffer[ 7],  6) + dd;
		bb = doRotateLeft(bb, 10);
		dd = doRotateLeft(dd + doF1(ee,aa,bb) + this.intBuffer[ 6],  8) + cc;
		aa = doRotateLeft(aa, 10);
		cc = doRotateLeft(cc + doF1(dd,ee,aa) + this.intBuffer[ 2], 13) + bb;
		ee = doRotateLeft(ee, 10);
		bb = doRotateLeft(bb + doF1(cc,dd,ee) + this.intBuffer[13],  6) + aa;
		dd = doRotateLeft(dd, 10);
		aa = doRotateLeft(aa + doF1(bb,cc,dd) + this.intBuffer[14],  5) + ee;
		cc = doRotateLeft(cc, 10);
		ee = doRotateLeft(ee + doF1(aa,bb,cc) + this.intBuffer[ 0], 15) + dd;
		bb = doRotateLeft(bb, 10);
		dd = doRotateLeft(dd + doF1(ee,aa,bb) + this.intBuffer[ 3], 13) + cc;
		aa = doRotateLeft(aa, 10);
		cc = doRotateLeft(cc + doF1(dd,ee,aa) + this.intBuffer[ 9], 11) + bb;
		ee = doRotateLeft(ee, 10);
		bb = doRotateLeft(bb + doF1(cc,dd,ee) + this.intBuffer[11], 11) + aa;
		dd = doRotateLeft(dd, 10);
		
		dd += c + this.h1;
		
		this.h1 = this.h2 + d + ee;
		this.h2 = this.h3 + e + aa;
		this.h3 = this.h4 + a + bb;
		this.h4 = this.h0 + b + cc;
		this.h0 = dd;
		
		this.intBufferOffset = 0;
		
		for(int i = 0; i < this.intBuffer.length; i++) {
			this.intBuffer[i] = 0;
		}
	}
	
	private void doProcessLength(final long bitLength) {
		if(this.intBufferOffset > 14) {
			doProcessBlock();
		}
		
		this.intBuffer[14] = (int)(bitLength & 0xFFFFFFFF);
		this.intBuffer[15] = (int)(bitLength >>> 32);
	}
	
	private void doProcessWord(final byte[] input, final int offset) {
		this.intBuffer[this.intBufferOffset++] = (input[offset] & 0xFF) | ((input[offset + 1] & 0xFF) << 8) | ((input[offset + 2] & 0xFF) << 16) | ((input[offset + 3] & 0xFF) << 24);
		
		if(this.intBufferOffset == 16) {
			doProcessBlock();
		}
	}
	
	////////////////////////////////////////////////////////////////////////////////////////////////////
	
	private static int doF1(final int x, final int y, final int z) {
		return x ^ y ^ z;
	}
	
	private static int doF2(final int x, final int y, final int z) {
		return (x & y) | (~x & z);
	}
	
	private static int doF3(final int x, final int y, final int z) {
		return (x | ~y) ^ z;
	}
	
	private static int doF4(final int x, final int y, final int z) {
		return (x & z) | (y & ~z);
	}
	
	private static int doF5(final int x, final int y, final int z) {
		return x ^ (y | ~z);
	}
	
	private static int doRotateLeft(final int x, final int n) {
		return (x << n) | (x >>> (32 - n));
	}
	
	private static void doUnpackWord(final int word, final byte[] bytes, final int offset) {
		bytes[offset + 0] = (byte)(word >>>  0);
		bytes[offset + 1] = (byte)(word >>>  8);
		bytes[offset + 2] = (byte)(word >>> 16);
		bytes[offset + 3] = (byte)(word >>> 24);
	}
}