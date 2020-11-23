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

/**
 * This {@code Main} class can be used as a reference and for testing.
 * 
 * @since 1.0.0
 * @author J&#246;rgen Lundgren
 */
public final class Main {
	private Main() {
		
	}
	
	////////////////////////////////////////////////////////////////////////////////////////////////////
	
	/**
	 * Called when this program is executed.
	 * 
	 * @param args the parameter arguments that are not used
	 */
	public static void main(final String[] args) {
		final PrivateKey privateKey = PrivateKey.parseStringHex("18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725");
//		final PrivateKey privateKey = PrivateKey.parseStringWIF("5J1F7GHadZG3sCCKHCwg8Jvys9xUbFsjLnGec4H125Ny1V9nR6V");
		
		final PublicKey publicKey = privateKey.toPublicKey();
		
		final Address addressC = publicKey.toAddress( true);
		final Address addressU = publicKey.toAddress(false);
		
		System.out.println("Private Key Dec:     " + privateKey.toStringDec());
		System.out.println("Private Key Hex:     " + privateKey.toStringHex());
		System.out.println("Private Key WIF M C: " + privateKey.toStringWIF( true, false));
		System.out.println("Private Key WIF M U: " + privateKey.toStringWIF(false, false));
		System.out.println("Private Key WIF T C: " + privateKey.toStringWIF( true,  true));
		System.out.println("Private Key WIF T U: " + privateKey.toStringWIF(false,  true));
		System.out.println();
		System.out.println("Public Key Dec C:    " + publicKey.toBigInteger( true).toString(10));
		System.out.println("Public Key Hex C:    " + publicKey.toBigInteger( true).toString(16));
		System.out.println("Public Key Dec U:    " + publicKey.toBigInteger(false).toString(10));
		System.out.println("Public Key Hex U:    " + publicKey.toBigInteger(false).toString(16));
		System.out.println();
		System.out.println("Address C:           " + addressC.toStringBase58());
		System.out.println("Address U:           " + addressU.toStringBase58());
		System.out.println();
		System.out.println("C:                   Compressed");
		System.out.println("U:                   Uncompressed");
		System.out.println("M:                   Mainnet");
		System.out.println("T:                   Testnet");
		System.out.println("WIF:                 Wallet Import Format");
	}
}