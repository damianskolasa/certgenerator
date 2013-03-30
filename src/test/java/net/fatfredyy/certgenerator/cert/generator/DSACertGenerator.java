package net.fatfredyy.certgenerator.cert.generator;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

import net.fatfredyy.certgenerator.cert.DSACertificateCreator;
import net.fatfredyy.certgenerator.keypair.DSAKeyPairGenerator;
import net.fatfredyy.certgenerator.keystore.CertKeyStoreCreator;
import net.fatfredyy.certgenerator.test.CertInfoUtil;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class DSACertGenerator {

	static List<String> digestAlgorithms = Arrays.asList("SHA1", "SHA256", "SHA384", "SHA512");

	/**
	 * @param args
	 */
	public static void main(String[] args) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		KeyPair generatedKeyPair = DSAKeyPairGenerator.generateDSAKeyPair(1024, 160);
		storeCert(generatedKeyPair, "1024-160"); 
		
		generatedKeyPair = DSAKeyPairGenerator.generateDSAKeyPair(2048, 224);
		storeCert(generatedKeyPair, "2048-224"); 

		generatedKeyPair = DSAKeyPairGenerator.generateDSAKeyPair(2048, 256);
		storeCert(generatedKeyPair, "2048-256"); 
		
		generatedKeyPair = DSAKeyPairGenerator.generateDSAKeyPair(3072, 256);
		storeCert(generatedKeyPair, "3072-256"); 

	}

	private static void storeCert(KeyPair generatedKeyPair, String spec) throws Exception {
		DSACertificateCreator dsaCertificateCreator = new DSACertificateCreator(CertInfoUtil.getNotBeforeDate(),
				CertInfoUtil.getNotAfterDate(), CertInfoUtil.getSubject(), BigInteger.ONE);
		for (String digestAlg : digestAlgorithms) {
			X509Certificate certificate = dsaCertificateCreator.createSelfSignedCertificate(generatedKeyPair, digestAlg + "withDSA");
			CertKeyStoreCreator certKeyStoreCreator = new CertKeyStoreCreator(certificate, generatedKeyPair.getPrivate());
			KeyStore keyStore = certKeyStoreCreator.creteKeyStore("privateKey", "certificate", "123456".toCharArray());
			String ksPath = "src/test/resources/ks_dsa_" + spec+"_" + digestAlg + ".p12";
			CertKeyStoreCreator.saveKeyStore(keyStore, ksPath, "132456".toCharArray());
			System.out.println("Creted ks: " + ksPath);

		}
	}

}
