package net.fatfredyy.certgenerator.keypair;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;

public class ECKeyPairGenerator {

	public static KeyPair generateECKeyPair(String ecName) throws Exception {
		ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(ecName);

		KeyPairGenerator g = KeyPairGenerator.getInstance("EC", "BC");
		g.initialize(ecSpec, new SecureRandom());
		
		KeyPair pair = g.generateKeyPair();
		
		return pair;
	}

}
