package net.fatfredyy.certgenerator.benchmark;

import java.io.File;
import java.io.FileWriter;
import java.security.KeyPair;
import java.security.Security;
import java.security.Signature;
import java.util.Arrays;
import java.util.List;

import net.fatfredyy.certgenerator.keypair.DSAKeyPairGenerator;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class DSASignaturesTimesReport {

	static List<String> digestAlgorithms = Arrays.asList("SHA1", "SHA256", "SHA384", "SHA512");

	public static void main(String[] args) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		String path = "target/dsa.csv";

		File file = new File(path);
		FileWriter fw = new FileWriter(file);

		fw.write("Key sizes;SHA1;SHA256;SHA384;SHA512;SHA1;SHA256;SHA384;SHA512\n");
		KeyPair generatedKeyPair = DSAKeyPairGenerator.generateDSAKeyPair(1024, 160);
		timeSignatureAndVerification("1024 - 160", generatedKeyPair, fw);
		
		generatedKeyPair = DSAKeyPairGenerator.generateDSAKeyPair(2048, 224);
		timeSignatureAndVerification("2048 - 224", generatedKeyPair, fw);
		
		generatedKeyPair = DSAKeyPairGenerator.generateDSAKeyPair(2048, 256);
		timeSignatureAndVerification("2048 - 256", generatedKeyPair, fw);
		
		generatedKeyPair = DSAKeyPairGenerator.generateDSAKeyPair(3072, 256);
		timeSignatureAndVerification("3072 - 256", generatedKeyPair, fw);
		
		fw.flush();
		fw.close();

	}
	
	private static void timeSignatureAndVerification(String spec,KeyPair keyPair, FileWriter fw) throws Exception{
		StringBuilder sbs = new StringBuilder();
		StringBuilder sbw = new StringBuilder();
		for (String digestAlg : digestAlgorithms) {
			long startSign = System.currentTimeMillis();
			Signature signer = Signature.getInstance(digestAlg + "withDSA", "BC");
			signer.initSign(keyPair.getPrivate());
			signer.update("TestSignatureString".getBytes());
			byte[] signature = signer.sign();
			long stopSign = System.currentTimeMillis();
			long startVrf = System.currentTimeMillis();
			signer.initVerify(keyPair.getPublic());
			signer.update("TestSignatureString".getBytes());
			boolean signatureValid = signer.verify(signature);
			long stopVrf = System.currentTimeMillis();
			sbs.append(";" + (stopSign - startSign));
			sbw.append(";" + (stopVrf - startVrf));

		}
		fw.write(spec + sbs.toString() + sbw.toString() + "\n");
	}

}
