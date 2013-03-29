package net.fatfredyy.certgenerator.keypair;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.RSAKeyGenParameterSpec;

public class RSAKeyPairGenerator {
	
	
	public static KeyPair generateRSAKeyPair(int keysize, BigInteger publicExponent) throws Exception {
		RSAKeyGenParameterSpec	rsaKeyGenParamSpec = new RSAKeyGenParameterSpec(keysize, publicExponent);	
		
		KeyPairGenerator g = KeyPairGenerator.getInstance("RSA", "BC");
		g.initialize(rsaKeyGenParamSpec, new SecureRandom());

		KeyPair pair = g.generateKeyPair();

		return pair;
	}

}
