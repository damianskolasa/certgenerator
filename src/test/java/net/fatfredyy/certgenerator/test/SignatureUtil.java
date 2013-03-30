package net.fatfredyy.certgenerator.test;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

public class SignatureUtil {
	
	
	public static boolean testSignAndVerify(PrivateKey privateKey, PublicKey publicKey, String algorithm) throws Exception {
		Signature signer = Signature.getInstance(algorithm, "BC");
		signer.initSign(privateKey);
		signer.update("TestSignatureString".getBytes());
		byte[] signature = signer.sign();

		signer.initVerify(publicKey);
		signer.update("TestSignatureString".getBytes());
		boolean signatureValid = signer.verify(signature);

		return signatureValid;
	}
}
