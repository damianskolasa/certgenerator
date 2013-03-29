package net.fatfredyy.certgenerator.keypair;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.DSAParameterSpec;

import org.bouncycastle.crypto.generators.DSAParametersGenerator;
import org.bouncycastle.crypto.params.DSAParameters;

public class DSAKeyPairGenerator {

	public static KeyPair generateDSAKeyPair(int size, int certainty) throws Exception {
		DSAParametersGenerator dsaParamsGen = new DSAParametersGenerator();
		dsaParamsGen.init(size, certainty, new SecureRandom());

		DSAParameters generatedDSAParams = dsaParamsGen.generateParameters();
		DSAParameterSpec dsaParamSpec = new DSAParameterSpec(generatedDSAParams.getP(), generatedDSAParams.getQ(),
				generatedDSAParams.getG());
		
		KeyPairGenerator g = KeyPairGenerator.getInstance("DSA", "BC");
		g.initialize(dsaParamSpec, new SecureRandom());

		KeyPair pair = g.generateKeyPair();

		return pair;
	}

}
