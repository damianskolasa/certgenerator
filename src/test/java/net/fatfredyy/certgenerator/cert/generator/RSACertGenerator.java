package net.fatfredyy.certgenerator.cert.generator;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Arrays;
import java.util.List;

import net.fatfredyy.certgenerator.cert.RSACertificateCreator;
import net.fatfredyy.certgenerator.keypair.RSAKeyPairGenerator;
import net.fatfredyy.certgenerator.keystore.CertKeyStoreCreator;
import net.fatfredyy.certgenerator.test.CertInfoUtil;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class RSACertGenerator {

	static List<String> digestAlgorithms = Arrays.asList("SHA1", "SHA256", "SHA384", "SHA512");

	/**
	 * @param args
	 */
	public static void main(String[] args) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		KeyPair generatedKeyPair = RSAKeyPairGenerator.generateRSAKeyPair(1024, RSAKeyGenParameterSpec.F4);
		storeCert(generatedKeyPair, "1024"); 
		
		generatedKeyPair = RSAKeyPairGenerator.generateRSAKeyPair(2048, RSAKeyGenParameterSpec.F4);
		storeCert(generatedKeyPair, "3072"); 

		generatedKeyPair = RSAKeyPairGenerator.generateRSAKeyPair(4096, RSAKeyGenParameterSpec.F4);
		storeCert(generatedKeyPair, "7680"); 
		
		generatedKeyPair = RSAKeyPairGenerator.generateRSAKeyPair(8192, RSAKeyGenParameterSpec.F4);
		storeCert(generatedKeyPair, "15360"); 

	}

	private static void storeCert(KeyPair generatedKeyPair, String spec) throws Exception {
		RSACertificateCreator rsaCertificateCreator = new RSACertificateCreator(CertInfoUtil.getNotBeforeDate(),
				CertInfoUtil.getNotAfterDate(), CertInfoUtil.getSubject(), BigInteger.ONE);
		for (String digestAlg : digestAlgorithms) {
			X509Certificate certificate = rsaCertificateCreator.createSelfSignedCertificate(generatedKeyPair, digestAlg + "withRSA");
			CertKeyStoreCreator certKeyStoreCreator = new CertKeyStoreCreator(certificate, generatedKeyPair.getPrivate());
			KeyStore keyStore = certKeyStoreCreator.creteKeyStore("privateKey", "certificate", "123456".toCharArray());
			String ksPath = "src/test/resources/ks_rsa_" + spec+"_" + digestAlg + ".p12";
			CertKeyStoreCreator.saveKeyStore(keyStore, ksPath, "132456".toCharArray());
			System.out.println("Creted ks: " + ksPath);

		}
	}

}
