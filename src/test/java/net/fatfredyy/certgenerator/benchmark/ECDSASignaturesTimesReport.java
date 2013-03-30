package net.fatfredyy.certgenerator.benchmark;

import java.io.File;
import java.io.FileWriter;
import java.security.KeyPair;
import java.security.Security;
import java.security.Signature;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;

import net.fatfredyy.certgenerator.keypair.ECDSAKeyPairGenerator;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class ECDSASignaturesTimesReport {
	
	static List<String> digestAlgorithms = Arrays.asList("SHA1", "SHA256", "SHA384", "SHA512");
	
	
	public static void main(String[] args) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		String path = "target/ecdsa_s.csv";
		Enumeration<String> en = ECNamedCurveTable.getNames();
		File file = new File(path);
		System.out.println(file.getCanonicalFile());
		FileWriter fw = new FileWriter(file);
		
		fw.write("Curve name;SHA1;SHA256;SHA384;SHA512;SHA1;SHA256;SHA384;SHA512\n");
		while(en.hasMoreElements()) {
			String curveName = en.nextElement();
			KeyPair generatedKeyPair = ECDSAKeyPairGenerator.generateECDSAKeyPair(curveName);
			StringBuilder sbs = new StringBuilder();
			StringBuilder sbw = new StringBuilder();
			for (String digestAlg : digestAlgorithms) {
				long startSign = System.currentTimeMillis();
				Signature signer = Signature.getInstance(digestAlg+"withECDSA", "BC");
				signer.initSign(generatedKeyPair.getPrivate());
				signer.update("TestSignatureString".getBytes());
				byte[] signature = signer.sign();
				long stopSign = System.currentTimeMillis();
				long startVrf = System.currentTimeMillis();
				signer.initVerify(generatedKeyPair.getPublic());
				signer.update("TestSignatureString".getBytes());
				boolean signatureValid = signer.verify(signature);
				long stopVrf = System.currentTimeMillis();
				sbs.append(";" +(stopSign - startSign));
				sbw.append(";" +(stopVrf - startVrf));
				
			}
			fw.write(curveName + sbs.toString() + sbw.toString() + "\n");
		}
		fw.flush();
		fw.close();
		
		
	}

}
