package net.fatfredyy.certgenerator;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Main {
	
	public static void main(String[] args) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		
		String assymetricKeyType = args[1];
		
		if (assymetricKeyType.equals("ecc")) {
			
		} else if (assymetricKeyType.equals("ecdsa")) {
			
		} else if (assymetricKeyType.equals("dsa")) {
			
		} else if (assymetricKeyType.equals("rsa")) {
			
		} else {
			System.err.println("Unknown assymetric key type");
		}
			
		
	}

}
