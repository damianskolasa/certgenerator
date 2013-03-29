package net.fatfredyy.certgenerator.keypair;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;

public class ECDSAKeyPairGenerator {
	
	public static KeyPair generateECDSAKeyPair(String ecName) throws Exception {
		ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(ecName);

		KeyPairGenerator g = KeyPairGenerator.getInstance("ECDSA", "BC");
		g.initialize(ecSpec, new SecureRandom());
		
		KeyPair pair = g.generateKeyPair();
		
		return pair;
	}


}
