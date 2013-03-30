package net.fatfredyy.certgenerator.benchmark;

import java.io.File;
import java.io.FileWriter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.Security;
import java.security.Signature;
import java.security.spec.RSAKeyGenParameterSpec;
import java.text.DecimalFormat;
import java.util.Arrays;
import java.util.List;

import net.fatfredyy.certgenerator.keypair.DSAKeyPairGenerator;
import net.fatfredyy.certgenerator.keypair.RSAKeyPairGenerator;

import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class RSASignaturesTimesReport {

	static List<String> digestAlgorithms = Arrays.asList("SHA1", "SHA256", "SHA384", "SHA512");

	public static void main(String[] args) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		String path = "target/rsa.csv";

		File file = new File(path);
		FileWriter fw = new FileWriter(file);

		fw.write("Key sizes;SHA1;SHA256;SHA384;SHA512;SHA1;SHA256;SHA384;SHA512\n");
		KeyPair generatedKeyPair = RSAKeyPairGenerator.generateRSAKeyPair(1024, RSAKeyGenParameterSpec.F4);
		timeSignatureAndVerification("1024", generatedKeyPair, fw);
		
		generatedKeyPair = RSAKeyPairGenerator.generateRSAKeyPair(2048, RSAKeyGenParameterSpec.F4);
		timeSignatureAndVerification("2048", generatedKeyPair, fw);
		
		generatedKeyPair = RSAKeyPairGenerator.generateRSAKeyPair(4096, RSAKeyGenParameterSpec.F4);
		timeSignatureAndVerification("4096", generatedKeyPair, fw);
		
		generatedKeyPair = RSAKeyPairGenerator.generateRSAKeyPair(8192, RSAKeyGenParameterSpec.F4);
		timeSignatureAndVerification("8192", generatedKeyPair, fw);
		
		fw.flush();
		fw.close();

	}
	
	private static void timeSignatureAndVerification(String spec,KeyPair keyPair, FileWriter fw) throws Exception{
		StringBuilder sbs = new StringBuilder();
		StringBuilder sbw = new StringBuilder();
		for (String digestAlg : digestAlgorithms) {
			long startSign = System.nanoTime();
			Signature signer = Signature.getInstance(digestAlg + "withRSA", "BC");
			signer.initSign(keyPair.getPrivate());
			signer.update("TestSignatureString".getBytes());
			byte[] signature = signer.sign();
			long stopSign = System.nanoTime();
			long startVrf = System.nanoTime();
			signer.initVerify(keyPair.getPublic());
			signer.update("TestSignatureString".getBytes());
			boolean signatureValid = signer.verify(signature);
			long stopVrf = System.nanoTime();
			double sign = (stopSign - startSign);
			sign = sign/1000000;
			double vrf = (stopVrf - startVrf);
			vrf = vrf/1000000;
			DecimalFormat decimalFormat = new DecimalFormat("####.##");
			sbs.append(";" + decimalFormat.format(sign));
			sbw.append(";" + decimalFormat.format(vrf));
			
			System.out.println(sbw.toString());

		}
		fw.write(spec + sbs.toString() + sbw.toString() + "\n");
	}

}
